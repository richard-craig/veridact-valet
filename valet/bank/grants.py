"""
Valet's grant service: one record per "customer let this agent do this", whoever ran the consent screen.

Federated mode: Valet's own consent screen calls create_grant (authz.py).
Native mode:    the bank's identity provider runs consent and registers the result here, then puts the returned
                grant id in the access tokens it issues (an Auth0 Action, a Keycloak protocol mapper, a PingFederate
                access-token mapping...). It can also check a grant's status before issuing or refreshing tokens.

Both modes get the same policy ceilings, pause and revoke, monthly ledger and receipts.

The internal endpoints are for the bank's IdP only. The PoC protects them with a shared secret
(VALET_INTERNAL_SECRET); a bank would use mTLS on its internal network.
"""
from __future__ import annotations

import json
import secrets
import time
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ..common.crypto import digest, random_id, sha256_b64u
from ..common.money import to_cents, to_str
from . import levels as L
from .context import Bank, OAuthError
from .registry import AgentRecord


def create_grant(bank: Bank, customer: dict[str, Any], agent: AgentRecord, level: str, account_id: str,
                 monthly_cents: int, via: str) -> dict[str, Any]:
    """Apply the bank's policy, store the grant and write the consent receipt. Raises ValueError on a bad choice."""
    cfg, store = bank.cfg, bank.store
    acct = store.one("SELECT * FROM accounts WHERE id=? AND customer=?", account_id, customer["id"])
    if not acct:
        raise ValueError("that account does not belong to this customer")
    if level not in L.LEVELS:
        raise ValueError(f"unknown access level {level!r}")
    monthly = min(int(monthly_cents), cfg.max_monthly_limit)            # the bank's ceiling always wins
    details = L.build_details(level, acct["id"], monthly)
    summary = L.plain_summary(level, details, f"{acct['name']} {acct['number']}", cfg.max_grant_days)
    consent_hash = digest({"summary": summary, "agent": agent.name, "operator": agent.operator,
                           "client_id": agent.client_id})
    gid, now = random_id("g", 12), time.time()
    store.x("INSERT INTO grants (id, customer, client_id, level, details, status, created, expires, jkt, consent_hash, "
            "sub, confirmed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", gid, customer["id"], agent.client_id, level,
            json.dumps(details), "active", now, now + cfg.max_grant_days * 86400, None, consent_hash,
            sha256_b64u(customer["id"] + agent.client_id)[:22], now)
    bank.receipts.append(grant_id=gid, agent=agent.client_id, customer=customer["id"], action="connect",
                         outcome="allowed", basis="consent", detail={"summary": summary, "via": via},
                         consent_hash=consent_hash)
    return store.grant(gid)


def keep_grant(bank: Bank, g: dict[str, Any], via: str) -> dict[str, Any]:
    """The customer reviewed this mandate and kept it as it is: same grant, same terms, a fresh confirmation time.
    Nothing about what the agent may do changes, so no new consent is recorded; the receipt says who kept it."""
    now = time.time()
    bank.store.x("UPDATE grants SET confirmed_at=? WHERE id=?", now, g["id"])
    bank.receipts.append(grant_id=g["id"], agent=g["client_id"], customer=g["customer"], action="reconfirm",
                         outcome="done", basis="customer", detail={"via": via, "status": g["status"]},
                         consent_hash=g["consent_hash"])
    return bank.store.grant(g["id"])


def end_grant(bank: Bank, g: dict[str, Any], reason: str) -> None:
    """Revoke a mandate the customer stopped or replaced at review."""
    bank.store.set_status(g["id"], "revoked")
    bank.receipts.append(grant_id=g["id"], agent=g["client_id"], customer=g["customer"], action="revoke",
                         outcome="done", basis="customer", reason=reason)


def router(bank: Bank) -> APIRouter:
    r = APIRouter(prefix="/internal")

    def authorised(request: Request) -> None:
        secret = bank.cfg.internal_secret
        given = request.headers.get("Authorization", "")
        if not secret:
            raise OAuthError("not_found", "the internal grant service is not enabled", 404)
        if not secrets.compare_digest(given, f"Bearer {secret}"):
            raise OAuthError("invalid_client", "the identity provider must authenticate to the grant service", 401)

    def view(g: dict[str, Any]) -> dict[str, Any]:
        return {"grant_id": g["id"], "status": g["status"], "client_id": g["client_id"], "level": g["level"],
                "authorization_details": g["details"], "expires_at": int(g["expires"]),
                "spent_this_month": to_str(bank.store.spent(g["id"]))}

    @r.post("/grants", status_code=201)
    async def register(request: Request):
        authorised(request)
        body = await request.json()
        customer = bank.store.customer_for_idp(str(body.get("customer", "")))
        if not customer:
            raise OAuthError("invalid_request", "no customer matches that identity")
        agent = bank.registry.lookup(str(body.get("client_id", "")))
        if not agent or not bank.registry.is_trusted(agent.client_id):
            raise OAuthError("unauthorized_client", "this agent is not verified, so the bank will not connect it")
        try:
            monthly = to_cents(body.get("monthly_limit", "2000.00"))
            g = create_grant(bank, dict(customer), agent, str(body.get("level", "view_only")),
                             str(body.get("account", "")), monthly, via="bank identity provider")
        except ValueError as e:
            raise OAuthError("invalid_request", str(e)) from e
        return JSONResponse(view(g), status_code=201)

    @r.delete("/grants/{grant_id}")
    def revoke(grant_id: str, request: Request):
        """The customer disconnected the agent in the IdP's own account pages: end the grant here too."""
        authorised(request)
        g = bank.store.grant(grant_id)
        if not g:
            raise OAuthError("not_found", "unknown grant", 404)
        if g["status"] != "revoked":
            bank.store.set_status(grant_id, "revoked")
            bank.receipts.append(grant_id=grant_id, agent=g["client_id"], customer=g["customer"], action="revoke",
                                 outcome="done", basis="customer", reason="disconnected in the bank's sign-in service")
        return view(bank.store.grant(grant_id))

    @r.get("/grants/{grant_id}")
    def status(grant_id: str, request: Request):
        authorised(request)
        g = bank.store.grant(grant_id)
        if not g:
            raise OAuthError("not_found", "unknown grant", 404)
        return view(g)

    return r
