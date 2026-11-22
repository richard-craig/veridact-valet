"""
The bank's Personal Agent Protocol (Poppy) surface (docs/poppy-extension.md):

- `/.well-known/poppy.json`: the bank's discovery document, with scope descriptions, Poppy's risk hints on each scope,
  and the draft `veridact.net/valet` extension that advertises mandates, approvals and receipts.
- A middleware that reads a `Poppy-Session` header, verifies it when it can, and makes it available to the receipt
  writer, so receipts carry the Session ID. A Session is evidence only: it never grants access.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, FastAPI, Request

from ..common.poppy import current_session, read_session

# Valet's access levels as Poppy scopes. The customer still builds the mandate on the bank's consent screen; the
# scope says which level the agent asks for.
SCOPES = {
    "accounts:read": "See balances and 90 days of transactions on the accounts you choose",
    "payments:approve-each": "Prepare payments to payees you choose; you approve every payment in the bank app",
    "payments:standing": "Pay payees you choose within limits you set, without asking each time",
}

# Poppy 1.1 section 4.7: `changes` is none, reversible or irreversible; `personal_data` says whether it reveals any.
SCOPE_HINTS = {
    "accounts:read": {"changes": "none", "personal_data": True},
    "payments:approve-each": {"changes": "irreversible", "personal_data": True},
    "payments:standing": {"changes": "irreversible", "personal_data": True},
}

# The same hints on Valet's own access levels and actions (docs/valet-profile.md section 2).
LEVEL_HINTS = {
    "view_only": SCOPE_HINTS["accounts:read"],
    "approved_payer": SCOPE_HINTS["payments:approve-each"],
    "bill_payer": SCOPE_HINTS["payments:standing"],
}
ACTION_HINTS = {
    "read_balances": {"changes": "none", "personal_data": True},
    "read_transactions": {"changes": "none", "personal_data": True},
    "pay_existing_beneficiary": {"changes": "irreversible", "personal_data": True},
}


def discovery(bank) -> dict[str, Any]:
    issuer = bank.cfg.issuer.rstrip("/")
    domain = urlsplit(issuer).netloc
    return {
        "protocol_version": "1.1",
        "organization": {"name": "Marula Bank", "domain": domain},
        "auth": {"issuer": issuer, "scopes": SCOPES, "scope_hints": SCOPE_HINTS},
        "apis": [
            {"type": "openapi", "url": f"{issuer}/openapi.json",
             "description": "Accounts, transactions and payments under a Valet mandate"},
            {"type": "mcp", "url": f"{issuer}/mcp",
             "description": "The same, as MCP tools for AI assistants"},
        ],
        "web": {"disabled": True},
        "extensions": {
            # Draft: not yet registered with Poppy. Requires Poppy's `operations` extension, version 3, for the
            # approval of one exact payment; adds standing mandates, approval in the bank app, reasons and receipts.
            "veridact.net/valet": [{
                "version": "1",
                "status": "draft",
                "spec": "https://github.com/richard-craig/veridact-valet/blob/main/docs/poppy-extension.md",
                "profile": "valet-profile/0.8",
                "levels": list(LEVEL_HINTS),
                "authorization_details_types": ["valet_accounts", "valet_payments", "valet_payment_once"],
                "approval_channels": ["bank_app"],
                "receipts": {"format": "valet-receipt+jwt", "keys": f"{issuer}/jwks"},
            }],
        },
    }


def router(bank) -> APIRouter:
    r = APIRouter()

    @r.get("/.well-known/poppy.json")
    def poppy_json():
        return discovery(bank)

    return r


def install(app: FastAPI, bank) -> None:
    """Read Poppy-Session headers on every request, for the receipts. Never refuses a request because of one."""

    def agent_jwk(client_id: str) -> dict[str, Any] | None:
        try:
            rec = bank.registry.lookup(client_id)
        except Exception:  # registry down: record the Session unverified rather than fail the request here
            return None
        return rec.jwk if rec and rec.jwk else None

    @app.middleware("http")
    async def poppy_session(request: Request, call_next):
        value = request.headers.get("Poppy-Session")
        if not value:
            return await call_next(request)
        auth = request.headers.get("Authorization", "")
        token = auth.split(" ", 1)[1] if " " in auth else None
        info = read_session(value, agent_jwk, bank.cfg.issuer.rstrip("/"), request.method, str(request.url), token)
        reset = current_session.set(info)
        try:
            return await call_next(request)
        finally:
            current_session.reset(reset)
