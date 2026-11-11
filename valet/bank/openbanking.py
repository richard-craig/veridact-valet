"""
The bank's open APIs for applications (accounts, transactions, payments), enforced by the Consent Service.

Every call: DPoP proof -> access token from the bank's IdP (Keycloak in the demo) -> key binding -> the token's
consent reference (valet_grant) -> POST-equivalent of /consent/v1/consent-decisions -> act, then settle. The decision
runs in-process here; a bank's API gateway calls the same contract over HTTP.

Account ids are consent-scoped (the app never sees internal ids or account numbers).
"""
from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Request

from ..common.dpop import DPoPError, check_proof
from ..common.money import to_cents, to_str
from .consents import ConsentService, Problem
from .context import Bank, OAuthError


def router(bank: Bank, svc: ConsentService) -> APIRouter:
    r = APIRouter(prefix="/ob/v1")
    store = bank.store
    me = "open-banking-api"

    def caller(request: Request) -> dict[str, Any]:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("DPoP "):
            raise OAuthError("invalid_token", "a DPoP-bound access token is required", 401)
        token = auth[5:]
        try:
            jkt = check_proof(request.headers.get("DPoP"), request.method, str(request.url), store.seen_jti,
                              access_token=token)
        except DPoPError as e:
            raise OAuthError("invalid_dpop_proof", str(e), 401) from e
        claims = bank.verify_access_token(token)
        if claims["cnf"]["jkt"] != jkt:
            raise OAuthError("invalid_token", "token is bound to a different key", 401)
        return claims

    def decide(claims: dict[str, Any], typ: str, action: str, resource_id: str | None = None,
               **extra: Any) -> dict[str, Any]:
        req = {"consent_id": claims["grant_id"], "client_id": claims["client_id"], "type": typ, "action": action,
               "context": {"resource_server": me}, **extra}
        if resource_id:
            req["resource"] = {"resource_type": "account", "resource_id": resource_id}
        return svc.decide(req, decider=me)

    def refuse(d: dict[str, Any]) -> None:
        status = 403
        raise Problem(status, "step_up_required" if d["decision"] == "step_up_required" else "insufficient_scope",
                      "The consent does not allow this" if d["decision"] == "deny" else "Customer approval needed",
                      d["reason"])

    def account_of(claims: dict[str, Any], resource_id: str) -> dict[str, Any] | None:
        c = svc.row(claims["grant_id"])
        for res in (c or {}).get("resources") or []:
            if res["resource_id"] == resource_id:
                return dict(store.one("SELECT * FROM accounts WHERE id=?", res["_account"]))
        return None

    def first_type(claims: dict[str, Any], types: tuple[str, ...]) -> str | None:
        c = svc.row(claims["grant_id"])
        return next((d["type"] for d in (c or {}).get("details") or [] if d["type"] in types), None)

    @r.get("/accounts")
    async def accounts(request: Request):
        claims = caller(request)
        d = decide(claims, "account_information", "read_accounts_basic")
        if d["decision"] != "permit":
            refuse(d)
        c = svc.row(claims["grant_id"])
        balances = decide(claims, "account_information", "read_balances")["decision"] == "permit"
        out = []
        for res in c["resources"]:
            a = store.one("SELECT * FROM accounts WHERE id=?", res["_account"])
            item = {"account_id": res["resource_id"], "display": res["display"], "currency": "ZAR"}
            if balances:
                item["balance"] = {"amount": to_str(a["balance"]), "currency": "ZAR"}
            out.append(item)
        return {"accounts": out}

    @r.get("/accounts/{account_id}/transactions")
    async def transactions(request: Request, account_id: str):
        claims = caller(request)
        d = decide(claims, "account_information", "read_transactions_detail", account_id)
        if d["decision"] != "permit":
            d = decide(claims, "account_information", "read_transactions_basic", account_id)
        if d["decision"] != "permit":
            refuse(d)
        a = account_of(claims, account_id)
        cons = d.get("constraints") or {}
        from .consents import parse_time
        lo = parse_time(cons["transactions_from"], "") if cons.get("transactions_from") else 0
        hi = parse_time(cons["transactions_to"], "") if cons.get("transactions_to") else time.time() + 86400
        rows = store.q("SELECT time, description, amount FROM transactions WHERE account=? AND time BETWEEN ? AND ? "
                       "ORDER BY time DESC", a["id"], lo, hi)
        return {"transactions": [{"booked_at": int(x["time"]), "description": x["description"],
                                  "amount": {"amount": to_str(abs(x["amount"])), "currency": "ZAR"},
                                  "direction": "credit" if x["amount"] > 0 else "debit"} for x in rows]}

    @r.post("/payments")
    async def pay(request: Request):
        claims = caller(request)
        body = await request.json()
        typ = first_type(claims, ("payment_initiation", "recurring_payment"))
        if not typ:
            raise Problem(403, "insufficient_scope", "The consent does not allow payments", "action_not_granted")
        try:
            cents = to_cents((body.get("amount") or {}).get("amount", ""))
        except ValueError as e:
            raise Problem(400, "invalid_request", "Invalid amount", str(e)) from e
        creditor = body.get("creditor") or {}
        to_acct = str((creditor.get("account") or {}).get("identification", ""))
        d = decide(claims, typ, "initiate_payment", body.get("from_account"), amount={"amount": to_str(cents), "currency": "ZAR"},
                   reserve=True, context={"resource_server": me, "creditor_account": to_acct,
                                          "reference": str(body.get("reference", ""))[:20]})
        if d["decision"] != "permit":
            refuse(d)
        a = account_of(claims, body.get("from_account", ""))
        if not a or a["balance"] < cents:
            svc.settle(d["decision_id"], "released")
            raise Problem(422, "invalid_request", "Insufficient funds")
        with store.tx():
            store.db.execute("UPDATE accounts SET balance=balance-? WHERE id=?", (cents, a["id"]))
            store.db.execute("INSERT INTO transactions (account,time,description,amount,by_agent) VALUES (?,?,?,?,?)",
                             (a["id"], time.time(), f"{creditor.get('name', 'Payment')} {body.get('reference', '')}".strip(),
                              -cents, claims["client_id"]))
        svc.settle(d["decision_id"], "confirmed")
        return {"status": "accepted", "amount": {"amount": to_str(cents), "currency": "ZAR"},
                "creditor": creditor.get("name"), "consent_id": claims["grant_id"]}

    return r
