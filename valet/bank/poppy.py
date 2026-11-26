"""
The bank's Personal Agent Protocol (Poppy) surface (docs/poppy-extension.md):

- `/.well-known/poppy.json`: the bank's discovery document, with scope descriptions, Poppy's risk hints on each scope,
  and the draft `veridact.net/valet` extension that advertises mandates, approvals, receipts and agent identity tiers.
- `/.well-known/oauth-protected-resource` (RFC 9728) for the bank's domain, naming Valet's authorisation server. The
  server's metadata lists the domain back under `protected_resources`, which is the pair of checks a Poppy agent runs
  before it trusts the issuer (Poppy 1.0, section 3).
- Scope-only sign-in: a Poppy agent that knows nothing about Valet asks for a Poppy scope; `details_for_scopes` turns it
  into a mandate template, and the customer builds the actual mandate on the bank's consent screen.
- A middleware that reads a `Poppy-Session` header, verifies it when it can, and makes it available to the receipt
  writer, so receipts carry the Session ID. A Session is evidence only: it never grants access.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import jwt
from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse

from ..common.poppy import VERSIONS, current_session, read_session

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


# Scope -> the access level it asks for. The scope only preselects the consent screen; the customer chooses the payees,
# limits and expiry, and Valet stores what the customer chose as authorization_details.
SCOPE_LEVEL = {"accounts:read": "view_only", "payments:approve-each": "approved_payer",
               "payments:standing": "bill_payer"}
# Each level includes the powers of the levels below it, so it implies their scopes. What a sign-in grants is the
# chosen level's scopes that the agent asked for: never a scope it didn't ask for (Poppy 1.1 section 4.7).
SCOPE_ORDER = ["accounts:read", "payments:approve-each", "payments:standing"]
IMPLIED = {"view_only": SCOPE_ORDER[:1], "approved_payer": SCOPE_ORDER[:2], "bill_payer": SCOPE_ORDER}
IGNORED_SCOPES = {"offline_access"}          # Valet always issues a refresh token; asking for one changes nothing
SPEC = "https://github.com/veridactlabs/veridact-valet/blob/main/docs/poppy-extension.md"


class ScopeError(ValueError):
    pass


def parse_scope(scope: str) -> list[str]:
    """The scopes a sign-in asks for, without offline_access. Unknown scopes, or none, are invalid_scope."""
    asked = [s for s in scope.split() if s not in IGNORED_SCOPES]
    unknown = [s for s in asked if s not in SCOPE_LEVEL]
    if unknown or not asked:
        raise ScopeError(f"unknown scope {unknown[0]!r}" if unknown else "no scope requested")
    return list(dict.fromkeys(asked))


def granted_scope(level: str, requested: list[str] | None) -> str:
    """The scope a grant at this level gives: its implied scopes, limited to those requested (all, if the agent asked
    with authorization_details alone)."""
    return " ".join(s for s in IMPLIED[level] if requested is None or s in requested)


def level_allowed(level: str, requested: list[str] | None) -> bool:
    """Can the customer choose this level for a request with these scopes? Not above the highest level asked for,
    and only if it grants at least one scope that was asked for."""
    if requested is None:
        return True
    order = list(LEVEL_HINTS)
    top = max((SCOPE_LEVEL[s] for s in requested), key=order.index)
    return order.index(level) <= order.index(top) and bool(granted_scope(level, requested))


def details_for_scopes(scope: str) -> list[dict[str, Any]]:
    """A Poppy scope request as Valet authorization_details: the template the consent screen starts from."""
    asked = parse_scope(scope)
    order = list(LEVEL_HINTS)
    level = max((SCOPE_LEVEL[s] for s in asked), key=order.index)
    details: list[dict[str, Any]] = [{"type": "valet_accounts", "actions": ["read_balances", "read_transactions"]}]
    if level != "view_only":
        details.append({"type": "valet_payments", "actions": ["pay_existing_beneficiary"], "approval": level})
    return details


def domain_resource(bank) -> str:
    """The bank's domain as an RFC 9728 resource identifier: what a Poppy agent signs in for."""
    p = urlsplit(bank.cfg.issuer)
    return f"{p.scheme}://{p.netloc}"


def protected_resource(bank) -> dict[str, Any]:
    issuer = bank.cfg.issuer.rstrip("/")
    return {"resource": domain_resource(bank), "authorization_servers": [issuer],
            "bearer_methods_supported": ["header"], "dpop_bound_access_tokens_required": True,
            "dpop_signing_alg_values_supported": ["ES256"], "scopes_supported": list(SCOPES),
            "authorization_details_types_supported": ["valet_accounts", "valet_payments", "valet_payment_once"],
            "resource_name": f"{bank.cfg.bank_name} (fictional) via Veridact Valet",
            "resource_documentation": SPEC}


def discovery(bank) -> dict[str, Any]:
    issuer = bank.cfg.issuer.rstrip("/")
    domain = urlsplit(issuer).netloc
    cimd = getattr(bank, "cimd", None)
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
                "spec": SPEC,
                "profile": "valet-profile/0.8",
                "levels": list(LEVEL_HINTS),
                "authorization_details_types": ["valet_accounts", "valet_payments", "valet_payment_once"],
                # A plain Poppy scope works: the bank turns it into a mandate the customer completes at consent.
                "scope_levels": SCOPE_LEVEL,
                # How the bank knows the agent, and the highest level each way allows (extension section 2.1).
                "agent_identity": {
                    "cimd": {"supported": cimd is not None, "max_level": "approved_payer"},
                    "veridact": {"supported": True, "max_level": "bill_payer",
                                 "spec": "https://veridact.net/docs/veridact/spec/"},
                },
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

    @r.get("/.well-known/oauth-protected-resource")
    def domain_metadata():
        return protected_resource(bank)

    return r


def install(app: FastAPI, bank) -> None:
    """Verify Poppy-Session headers (Poppy 1.1 sections 3.4 and 5.3) and hand verified Sessions to the receipts.

    A request with a Session header must also say which Poppy version it speaks (`Poppy-Version`), or it is refused
    with `version_unsupported`. One whose Session fails verification is refused with `invalid_session` (HTTP 400, not
    401, so the agent's OAuth library keeps a good access token). A request without the header goes on as before:
    Valet never needs a Session to act, only to record one."""

    class RegistryDown(Exception):
        pass

    def agent_jwk(client_id: str, kid: str | None) -> dict[str, Any] | None:
        try:
            rec = bank.registry.lookup(client_id)
        except Exception as e:
            raise RegistryDown() from e
        return rec.key_for(kid) if rec else None

    def refuse(error: str, why: str | None = None, status: int = 400) -> JSONResponse:
        body = {"error": error} | ({"error_description": why} if why else {})
        return JSONResponse(body, status_code=status, headers={"Cache-Control": "no-store"})

    @app.middleware("http")
    async def poppy_session(request: Request, call_next):
        value = request.headers.get("Poppy-Session")
        if not value:
            return await call_next(request)
        version = request.headers.get("Poppy-Version", "").strip()
        if version.split(".")[0] != "1" or version not in VERSIONS:
            return refuse("version_unsupported", f"this bank serves Poppy {', '.join(VERSIONS)}")
        auth = request.headers.get("Authorization", "")
        token = auth.split(" ", 1)[1] if " " in auth else None
        try:
            info = read_session(value, agent_jwk, bank.cfg.issuer.rstrip("/"), request.method, str(request.url), token)
        except RegistryDown:
            # The bank can't check the agent's keys right now. The request is judged on its token and mandate as
            # usual (and a payment waits for the registry anyway); the Session just isn't recorded.
            info = {"protocol": "poppy", "verified": False, "why": "registry_unavailable"}
        else:
            if info["verified"] and token and _token_client(token) not in (None, info.get("iss")):
                info |= {"verified": False, "why": "token_client"}     # step 3: same client_id as the Session
            if not info["verified"]:
                return refuse("invalid_session", info.get("why"))
        info["version"] = version
        reset = current_session.set(info)
        try:
            return await call_next(request)
        finally:
            current_session.reset(reset)


def _token_client(token: str) -> str | None:
    """The client_id an access token was issued to, if it says (the API verifies the token itself)."""
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return None
    return claims.get("client_id") if isinstance(claims.get("client_id"), str) else None
