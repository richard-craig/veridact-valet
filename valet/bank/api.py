"""
The bank API the agent calls, with Valet enforcement on every request (design section 5):

  1 DPoP proof   2 token   3 proof key = cnf.jkt   4 agent trusted   5 grant active (live)
  6 action in authorization_details   7 limits / existing beneficiary, with the amount held in one locked step
  8 instruct the bank's core banking API (Valet never executes), record the outcome, write a receipt
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from ..common.crypto import digest
from ..common.dpop import DPoPError, check_proof
from ..common.money import to_cents, to_str
from . import levels as L
from . import mandate
from .authz import _payment_summary, payment_detail
from .context import Bank, OAuthError
from .registry import RegistryUnavailable
from .payments import HELD


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
    store, receipts, payments = bank.store, bank.receipts, bank.payments

    def receipt(c: Caller, action: str, outcome: str, basis: str, **kw: Any) -> dict[str, Any]:
        return receipts.append(grant_id=c.grant["id"], agent=c.grant["client_id"], customer=c.grant["customer"],
                               action=action, outcome=outcome, basis=basis, grant_level=c.grant["level"], **kw)

    def authenticate(request: Request, payment: bool = False) -> Caller:
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
        act = claims.get("act")
        if act is not None and (not isinstance(act, dict) or act.get("sub") != claims["client_id"]):
            raise OAuthError("invalid_token", "the token's actor (act) is not the agent it was issued to", 401)
        # The binding tuple: issuer, client id, mandate id and key thumbprint must all match the grant.
        # Valet's own single-use approval tokens (its CIBA, still used in native mode) are the one other issuer.
        own_approval = claims.get("iss") == bank.cfg.issuer and claims.get("once") and not claims.get("external")
        if grant.get("issuer") and claims.get("iss") != grant["issuer"] and not own_approval:
            raise OAuthError("invalid_token", "token is from a different issuer than this grant", 401)
        if claims.get("external"):
            # Native mode: the grant was bound to the agent's key at consent (the IdP passed dpop_jkt in the hand-off
            # ticket or to /internal/grants). A grant with no key is refused, unless the bank has turned on binding
            # at first use for an IdP that cannot pass the key yet (weaker: the first valid token claims the grant).
            if not grant["jkt"]:
                if not bank.cfg.allow_first_use_binding:
                    raise OAuthError("invalid_token", "this grant was not bound to an agent key at consent", 401)
                if store.x("UPDATE grants SET jkt=? WHERE id=? AND jkt IS NULL", jkt, grant["id"]) == 1:
                    receipts.append(grant_id=grant["id"], agent=grant["client_id"], customer=grant["customer"],
                                    action="key_binding", outcome="done", basis="first_use", jkt=jkt)
                grant = store.grant(grant["id"])
            if grant["jkt"] != jkt:
                raise OAuthError("invalid_token", "token is bound to a different key from this grant", 401)
        caller = Caller(claims, grant)
        why = bank.denied(claims["client_id"], jkt)
        if why:
            receipt(caller, request.url.path, "refused", "refused", reason="denylisted")
            raise OAuthError("agent_denied", why, 403)
        try:
            trusted = bank.registry.is_trusted(claims["client_id"], for_payment=payment)
        except RegistryUnavailable as e:
            receipt(caller, request.url.path, "refused", "refused", reason="registry_unavailable")
            raise OAuthError("registry_unavailable", "the bank cannot check this agent right now; payments fail "
                                                     "closed. Try again later.", 503) from e
        if not trusted:
            receipt(caller, request.url.path, "refused", "refused", reason="agent_untrusted")
            raise OAuthError("agent_untrusted", "the bank no longer trusts this agent's operator", 403)
        if grant["status"] != "active":
            receipt(caller, request.url.path, "refused", "refused", reason=f"grant_{grant['status']}")
            raise OAuthError(f"grant_{grant['status']}", f"the customer's permission is {grant['status']}", 403)
        return caller

    def caller(request: Request) -> Caller:
        return authenticate(request)

    def payer(request: Request) -> Caller:
        """A request that can move money: the registry must be reachable (fail closed)."""
        return authenticate(request, payment=True)

    def allowed(c: Caller, typ: str, action: str, account: str | None = None) -> dict[str, Any] | None:
        d = L.find(c.details, typ)
        if d and action in d.get("actions", []) and (account is None or account in d.get("accounts", [])):
            return d
        return None

    # -------------------------------------------------------------- the agent's own grant
    @r.get("/grant")
    async def my_grant(c: Caller = Depends(caller)):
        """What the customer actually granted (OAuth Grant Management style). Needed in native mode, where the bank's
        IdP may not return authorization_details (Keycloak has no RAR); the customer may also have chosen less."""
        g = c.grant
        receipt(c, "read_grant", "allowed", "grant")
        return {"grant_id": g["id"], "status": g["status"], "level": g["level"], "authorization_details": g["details"],
                "expires_at": int(g["expires"]), "spent_this_month": to_str(store.spent(g["id"]))}

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
    # Valet decides and holds; the bank's core banking API executes (payments.py, core.py; design section 5.1).
    def answer(intent: dict[str, Any], c: Caller) -> JSONResponse:
        status, body = payments.response(intent, c.grant)
        return JSONResponse(body, status_code=status)

    def offer(c: Caller, intent: dict[str, Any]) -> None:
        """Hold a payment for the customer: 403 approval_required with the exact action the agent may ask for."""
        store.x("INSERT OR REPLACE INTO hints VALUES (?,?,?,?)", c.grant["id"], intent["request_digest"],
                json.dumps({**intent["detail"], "_reason": intent["reason"]}), time.time() + bank.cfg.approval_ttl)
        raise OAuthError("approval_required", intent["reason"], 403, authorization_details=[intent["detail"]],
                         payment_intent_id=intent["id"], reason=intent.get("reason_code"))

    @r.post("/payments")
    async def pay(request: Request, c: Caller = Depends(payer)):
        body = await request.json()
        try:
            cents = to_cents(body["amount"])
            frm, to_name, to_acct = body["from_account"], str(body["to"]["name"]), str(body["to"]["account"])
        except (KeyError, TypeError, ValueError) as e:
            raise OAuthError("invalid_request", f"payment needs from_account, to.name, to.account and amount: {e}") from e
        key = request.headers.get("Idempotency-Key", "")
        if not 8 <= len(key) <= 64:
            raise OAuthError("invalid_request", "an Idempotency-Key header of 8 to 64 characters is required: send the "
                                                "same key when you retry a payment, and a new key for a new payment")
        reference = str(body.get("reference", ""))[:40]
        # The agent's own account of what it was asked to do: recorded as agent-supplied, never trusted, kept outside
        # the receipt chain (receipts.py).
        instruction = " ".join(str(body.get("instruction", "")).split())[:200] or None
        detail = payment_detail(frm, to_name, to_acct, cents, reference)
        summary = _payment_summary(detail)

        if c.once:
            return pay_once(c, key, detail, summary)

        p = allowed(c, "valet_payments", "pay_existing_beneficiary", frm)
        if not p:
            receipt(c, "payment", "refused", "refused", reason="insufficient_authorization", detail=summary)
            raise OAuthError("insufficient_authorization", "this access level cannot make payments", 403)

        d = digest(detail)
        # One locked step: find or create the intent, check it against the mandate (payee, cap, count, limit counting
        # holds, approval mode; mandate.py), and hold the amount.
        with store.tx():
            intent, new = payments.by_key(c.grant["id"], key), False
            if intent is None:
                new = True
                check = mandate.check_payment(store, c.grant, to_acct, cents)
                agent = bank.registry.lookup(c.grant["client_id"])
                if check.covered and agent and not L.within(c.grant["level"], agent.ceiling):
                    # The grant was made at a higher tier than the agent holds now (its Veridact credential was
                    # withdrawn but its domain is still approved): every payment goes back to the customer.
                    check = mandate.Check(False, "approved_payer", "this agent is now identified only by its website, "
                                                                   "so you approve every payment it makes")
                if check.covered:
                    intent = payments.create(c.grant, key, d, detail, cents, "reserved", "grant", instruction=instruction)
                else:
                    intent = payments.create(c.grant, key, d, detail, cents, "approval_required", "grant",
                                             reason=check.text, expires=time.time() + bank.cfg.approval_ttl,
                                             reason_code=check.reason, instruction=instruction)
        if intent["request_digest"] != d:
            receipt(c, "payment", "refused", "refused", reason="idempotency key reused for a different payment", detail=summary)
            raise OAuthError("idempotency_key_reused", "this Idempotency-Key was used for a different payment; "
                                                       "use a new key for a new payment", 422)
        if intent["status"] == "approval_required":
            if new:
                receipt(c, "payment", "held", "approval_required", reason=intent["reason"], detail=summary,
                        payment_intent=intent["id"], idempotency_key=key, reason_code=intent["reason_code"],
                        agent_supplied_instruction=intent["instruction"])
            else:
                rearm(intent)
            offer(c, intent)
        if intent["status"] in HELD:                             # new, or a retry of one the bank has not answered
            intent = payments.execute(intent, c.grant)
        return answer(intent, c)

    def rearm(intent: dict[str, Any]) -> None:
        """A retry of a held payment whose approval was declined or ran out: let the agent ask the customer again."""
        ap = store.one("SELECT status, expires FROM approvals WHERE id=?", intent["approval"] or "")
        if ap and (ap["status"] in ("denied", "cancelled", "expired") or ap["expires"] < time.time()):
            store.x("UPDATE payment_intents SET approval=NULL WHERE id=? AND status='approval_required'", intent["id"])

    def pay_once(c: Caller, key: str, detail: dict[str, Any], summary: dict[str, Any]):
        """A single-use token for one approved action. It can only finish the payment the bank held for approval:
        the same Idempotency-Key, the same payment, once. Valet's own approvals and, in native mode, the bank's
        authorisation server's (e.g. CIBA with RAR) are both checked against that held intent."""
        d, approved_ref = digest(detail), None
        intent = payments.by_key(c.grant["id"], key)
        if intent and intent["request_digest"] == d and intent["status"] != "approval_required" and intent["basis"] == "approval":
            ref = f"idp:{c.claims.get('jti')}" if c.external else c.claims.get("approval")
            if intent["approval"] == ref:                         # a retry of the approved payment: never pays twice
                if intent["status"] in HELD:
                    intent = payments.execute(intent, c.grant)
                return answer(intent, c)

        def refuse(problem: str):
            receipt(c, "payment", "refused", "refused", reason=problem, detail=summary,
                    approval=None if c.external else c.claims.get("approval"))
            raise OAuthError("approval_invalid", problem, 403)

        if c.external:
            approved = c.claims["authorization_details"][0]
            if digest(approved) != d:
                refuse("this payment differs from what the customer approved")
            if not store.one("SELECT 1 FROM hints WHERE grant_id=? AND digest=? AND expires>?", c.grant["id"], d, time.time()):
                refuse("the bank did not offer this action for approval (or the offer expired)")
            if not c.claims.get("jti"):
                refuse("this approval has already been used")
            approved_ref = f"idp:{c.claims['jti']}"
        else:
            ap = store.one("SELECT * FROM approvals WHERE id=?", c.claims.get("approval", ""))
            if not ap or ap["grant_id"] != c.grant["id"]:
                refuse("unknown approval")
            if ap["status"] != "approved":
                refuse(f"approval is {ap['status']}")
            if ap["consumed"]:
                refuse("this approval has already been used")
            if ap["expires"] < time.time():
                refuse("this approval has expired")
            if d != ap["digest"]:
                refuse("this payment differs from what the customer approved")
            approved_ref = ap["id"]
        if not intent or intent["request_digest"] != d:
            refuse("no held payment matches this Idempotency-Key: send the approved payment with the key of the request "
                   "the bank held")
        if not c.external and intent["approval"] != approved_ref:
            refuse("this approval belongs to a different payment request")

        # The single-use gate, in one locked step: spend the approval and move the intent to reserved, or neither.
        with store.tx():
            if c.external:
                spent_once = not store.seen_jti("once:" + str(c.claims["jti"]), ttl=max(60, c.claims["exp"] - time.time() + 60))
            else:
                spent_once = store.db.execute("UPDATE approvals SET consumed=1 WHERE id=? AND consumed=0",
                                              (approved_ref,)).rowcount == 1
            ok = spent_once and payments.reserve_approved(intent, approved_ref)
            if ok:
                store.db.execute("DELETE FROM hints WHERE grant_id=? AND digest=?", (c.grant["id"], d))
        if not ok:
            refuse("this approval has already been used")
        return answer(payments.execute(payments.get(intent["id"]), c.grant), c)

    @r.get("/payments/{intent_id}")
    async def payment_status(intent_id: str, c: Caller = Depends(caller)):
        """Where a payment stands. Read-only: to move a pending payment on, retry it with the same Idempotency-Key."""
        intent = payments.get(intent_id)
        if not intent or intent["grant_id"] != c.grant["id"]:
            raise OAuthError("not_found", "no such payment for this grant", 404)
        return {"payment_intent_id": intent["id"], "state": intent["status"], "amount": to_str(intent["amount"]),
                "currency": "ZAR", "to": intent["detail"]["to"]["name"], "bank_payment_id": intent["bank_payment_id"],
                "reason": intent["reason"]}

    return r
