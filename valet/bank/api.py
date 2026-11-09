"""
The bank API the agent calls, with Valet enforcement on every request (design section 5):

  1 DPoP proof   2 token   3 proof key = cnf.jkt   4 agent trusted   5 grant active (live)
  6 action in authorization_details   7 limits / existing beneficiary   8 execute + receipt
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Depends, Request

from ..common.crypto import digest
from ..common.dpop import DPoPError, check_proof
from ..common.money import rand, to_cents, to_str
from . import levels as L
from .authz import _payment_summary, payment_detail
from .context import Bank, OAuthError
from .store import month_key


@dataclass
class Caller:
    claims: dict[str, Any]
    grant: dict[str, Any]

    @property
    def external(self) -> bool:
        """Issued by the bank's own authorisation server (native mode) rather than Valet's."""
        return bool(self.claims.get("external"))

    @property
    def once(self) -> bool:
        """A single-use token for one approved action."""
        if self.claims.get("once"):
            return True
        d = self.claims.get("authorization_details") or []
        return self.external and len(d) == 1 and d[0].get("type") == "valet_payment_once"

    @property
    def details(self) -> list[dict[str, Any]]:
        # Native mode: what the customer consented to is the grant registered with Valet, whatever the token says.
        if self.external and not self.once:
            return self.grant["details"]
        return self.claims["authorization_details"]


def router(bank: Bank) -> APIRouter:
    r = APIRouter(prefix="/api")
    store, receipts = bank.store, bank.receipts

    def receipt(c: Caller, action: str, outcome: str, basis: str, **kw: Any) -> dict[str, Any]:
        return receipts.append(grant_id=c.grant["id"], agent=c.grant["client_id"], customer=c.grant["customer"],
                               action=action, outcome=outcome, basis=basis, grant_level=c.grant["level"], **kw)

    def authenticate(request: Request) -> Caller:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("DPoP "):
            raise OAuthError("invalid_token", "a DPoP-bound access token is required", 401)
        token = auth[5:]
        try:
            jkt = check_proof(request.headers.get("DPoP"), request.method, str(request.url), store.seen_jti, access_token=token)
        except DPoPError as e:
            raise OAuthError("invalid_dpop_proof", str(e), 401) from e
        claims = bank.verify_access_token(token)
        if claims["cnf"]["jkt"] != jkt:
            raise OAuthError("invalid_token", "token is bound to a different key", 401)
        grant = store.grant(claims["grant_id"])
        if not grant:
            raise OAuthError("invalid_token", "unknown grant", 401)
        if grant["client_id"] != claims["client_id"]:
            raise OAuthError("invalid_token", "token and grant name different agents", 401)
        if claims.get("external"):
            # Native mode: the IdP bound the token to the agent's key; bind the grant to that key on first use,
            # so later tokens for this grant (and Valet's own approval tokens) must come from the same key.
            if not grant["jkt"]:
                store.x("UPDATE grants SET jkt=? WHERE id=? AND jkt IS NULL", jkt, grant["id"])
                grant = store.grant(grant["id"])
            if grant["jkt"] != jkt:
                raise OAuthError("invalid_token", "token is bound to a different key from this grant", 401)
        caller = Caller(claims, grant)
        if not bank.registry.is_trusted(claims["client_id"]):
            receipt(caller, request.url.path, "refused", "refused", reason="agent_untrusted")
            raise OAuthError("agent_untrusted", "the bank no longer trusts this agent's operator", 403)
        if grant["status"] != "active":
            receipt(caller, request.url.path, "refused", "refused", reason=f"grant_{grant['status']}")
            raise OAuthError(f"grant_{grant['status']}", f"the customer's permission is {grant['status']}", 403)
        return caller

    def caller(request: Request) -> Caller:
        return authenticate(request)

    def allowed(c: Caller, typ: str, action: str, account: str | None = None) -> dict[str, Any] | None:
        d = L.find(c.details, typ)
        if d and action in d.get("actions", []) and (account is None or account in d.get("accounts", [])):
            return d
        return None

    # -------------------------------------------------------------- reads
    @r.get("/accounts")
    async def accounts(c: Caller = Depends(caller)):
        d = allowed(c, "valet_accounts", "read_balances")
        if not d:
            receipt(c, "read_balances", "refused", "refused", reason="insufficient_authorization")
            raise OAuthError("insufficient_authorization", "not permitted to read balances", 403)
        rows = [store.one("SELECT id,name,number,balance FROM accounts WHERE id=?", a) for a in d["accounts"]]
        receipt(c, "read_balances", "allowed", "grant")
        return {"accounts": [{"id": x["id"], "name": x["name"], "number": x["number"], "balance": to_str(x["balance"]),
                              "currency": "ZAR"} for x in rows if x]}

    @r.get("/accounts/{account_id}/transactions")
    async def transactions(account_id: str, c: Caller = Depends(caller)):
        d = allowed(c, "valet_accounts", "read_transactions", account_id)
        if not d:
            receipt(c, "read_transactions", "refused", "refused", reason="insufficient_authorization")
            raise OAuthError("insufficient_authorization", "not permitted to read this account", 403)
        since = time.time() - d.get("history_days", 90) * 86400
        rows = store.q("SELECT time,description,amount,by_agent FROM transactions WHERE account=? AND time>? ORDER BY time DESC",
                       account_id, since)
        receipt(c, "read_transactions", "allowed", "grant")
        return {"transactions": [{"time": int(x["time"]), "description": x["description"], "amount": to_str(abs(x["amount"])),
                                  "direction": "in" if x["amount"] > 0 else "out", "by_agent": x["by_agent"]} for x in rows]}

    # ------------------------------------------------------- never allowed
    @r.post("/beneficiaries")
    async def add_beneficiary(request: Request, c: Caller = Depends(caller)):
        body = await request.json()
        receipt(c, "add_beneficiary", "refused", "refused", reason="agents can never add beneficiaries",
                detail={"name": str(body.get("name", ""))[:60]})
        raise OAuthError("insufficient_authorization",
                         "agents can never add beneficiaries; the customer must do this in the bank app", 403)

    # ------------------------------------------------------------ payments
    @r.post("/payments")
    async def pay(request: Request, c: Caller = Depends(caller)):
        body = await request.json()
        try:
            cents = to_cents(body["amount"])
            frm, to_name, to_acct = body["from_account"], str(body["to"]["name"]), str(body["to"]["account"])
        except (KeyError, TypeError, ValueError) as e:
            raise OAuthError("invalid_request", f"payment needs from_account, to.name, to.account and amount: {e}") from e
        reference = str(body.get("reference", ""))[:40]
        detail = payment_detail(frm, to_name, to_acct, cents, reference)
        summary = _payment_summary(detail)

        if c.once:
            return pay_once_external(c, detail, summary) if c.external else pay_once(c, detail, summary)

        p = allowed(c, "valet_payments", "pay_existing_beneficiary", frm)
        if not p:
            receipt(c, "payment", "refused", "refused", reason="insufficient_authorization", detail=summary)
            raise OAuthError("insufficient_authorization", "this access level cannot make payments", 403)

        cus = c.grant["customer"]
        existing = store.one("SELECT * FROM beneficiaries WHERE customer=? AND account=?", cus, to_acct)
        limit = L.monthly_limit(c.details) or 0
        spent = store.spent(c.grant["id"])
        if existing and spent + cents <= limit:
            res = execute(c, frm, to_name, cents, reference)
            store.x("INSERT INTO ledger VALUES (?,?,?) ON CONFLICT(grant_id,month) DO UPDATE SET spent=spent+excluded.spent",
                    c.grant["id"], month_key(), cents)
            rec = receipt(c, "payment", "allowed", "grant", detail=summary)
            return {**res, "receipt": rec["hash"], "spent_this_month": to_str(spent + cents), "monthly_limit": to_str(limit)}

        reason = (f"{to_name} is not a saved beneficiary on this account" if not existing else
                  f"{rand(cents)} would take this month to {rand(spent + cents)}, over the {rand(limit)} limit")
        d = digest(detail)
        store.x("INSERT OR REPLACE INTO hints VALUES (?,?,?,?)", c.grant["id"], d,
                json.dumps({**detail, "_reason": reason}), time.time() + bank.cfg.approval_ttl)
        receipt(c, "payment", "held", "approval_required", reason=reason, detail=summary)
        raise OAuthError("approval_required", reason, 403, authorization_details=[detail])

    def pay_once(c: Caller, detail: dict[str, Any], summary: dict[str, Any]):
        ap = store.one("SELECT * FROM approvals WHERE id=?", c.claims.get("approval", ""))
        problem = None
        if not ap or ap["grant_id"] != c.grant["id"]:
            problem = "unknown approval"
        elif ap["status"] != "approved":
            problem = f"approval is {ap['status']}"
        elif ap["consumed"]:
            problem = "this approval has already been used"
        elif ap["expires"] < time.time():
            problem = "this approval has expired"
        elif digest(detail) != ap["digest"]:
            problem = "this payment differs from what the customer approved"
        if problem:
            receipt(c, "payment", "refused", "refused", reason=problem, detail=summary, approval=c.claims.get("approval"))
            raise OAuthError("approval_invalid", problem, 403)
        with store.tx():
            store.db.execute("UPDATE approvals SET consumed=1 WHERE id=?", (ap["id"],))
        res = execute(c, detail["from"], detail["to"]["name"], to_cents(detail["amount"]["amount"]), detail.get("reference", ""))
        rec = receipt(c, "payment", "allowed", "approval", approval=ap["id"], detail=summary)
        return {**res, "receipt": rec["hash"]}

    def pay_once_external(c: Caller, detail: dict[str, Any], summary: dict[str, Any]):
        """Native mode: the bank's own authorisation server ran the approval (e.g. CIBA with RAR) and issued a
        single-use token for exactly one valet_payment_once. Valet still insists the action was one it offered,
        that it matches, and that the token is spent once."""
        approved = c.claims["authorization_details"][0]
        d = digest(detail)
        problem = None
        hint = store.one("SELECT * FROM hints WHERE grant_id=? AND digest=? AND expires>?", c.grant["id"], d, time.time())
        if digest(approved) != d:
            problem = "this payment differs from what the customer approved"
        elif not hint:
            problem = "the bank did not offer this action for approval (or the offer expired)"
        elif not c.claims.get("jti") or store.seen_jti("once:" + str(c.claims["jti"]),
                                                       ttl=max(60, c.claims["exp"] - time.time() + 60)):
            problem = "this approval has already been used"
        if problem:
            receipt(c, "payment", "refused", "refused", reason=problem, detail=summary)
            raise OAuthError("approval_invalid", problem, 403)
        store.x("DELETE FROM hints WHERE grant_id=? AND digest=?", c.grant["id"], d)
        res = execute(c, detail["from"], detail["to"]["name"], to_cents(detail["amount"]["amount"]), detail.get("reference", ""))
        rec = receipt(c, "payment", "allowed", "approval", approval=f"idp:{c.claims['jti']}", detail=summary)
        return {**res, "receipt": rec["hash"]}

    def execute(c: Caller, frm: str, to_name: str, cents: int, reference: str) -> dict[str, Any]:
        acct = store.one("SELECT * FROM accounts WHERE id=? AND customer=?", frm, c.grant["customer"])
        if not acct:
            raise OAuthError("invalid_request", "unknown account", 400)
        if acct["balance"] < cents:
            raise OAuthError("insufficient_funds", "not enough money in the account", 422)
        store.x("UPDATE accounts SET balance=balance-? WHERE id=?", cents, frm)
        store.x("INSERT INTO transactions (account,time,description,amount,by_agent) VALUES (?,?,?,?,?)",
                frm, time.time(), f"To {to_name}" + (f" ({reference})" if reference else ""), -cents, c.grant["client_id"])
        return {"status": "paid", "to": to_name, "amount": to_str(cents), "currency": "ZAR"}

    return r
