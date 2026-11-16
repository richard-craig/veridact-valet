"""Everything the bank's routes share: config, store, keys, registry, receipts, client authentication."""
from __future__ import annotations

import time
from typing import Any

import jwt
from fastapi.responses import JSONResponse

from ..common.crypto import Key, verify
from .config import BankConfig
from .core import CoreBanking, DemoCore
from .idp import OidcConfig, OidcSignIn
from .payments import Payments
from .receipts import Receipts
from .registry import AgentRecord, StaticRegistry
from .store import Store
from .tokens import ExternalIssuer, TokenRejected, external_issuers_from_env

JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def _loopback(url: str) -> bool:
    from urllib.parse import urlparse
    return (urlparse(url).hostname or "") in ("localhost", "127.0.0.1", "::1")


class OAuthError(Exception):
    def __init__(self, error: str, description: str, status: int = 400, **extra: Any):
        self.error, self.description, self.status, self.extra = error, description, status, extra

    def response(self) -> JSONResponse:
        headers = {"WWW-Authenticate": f'DPoP error="{self.error}"'} if self.status == 401 else None
        return JSONResponse({"error": self.error, "error_description": self.description, **self.extra},
                            status_code=self.status, headers=headers)


class Bank:
    def __init__(self, cfg: BankConfig | None = None, registry: StaticRegistry | None = None,
                 signin: OidcSignIn | None = None, external_issuers: dict[str, ExternalIssuer] | None = None,
                 core: CoreBanking | None = None):
        self.cfg = cfg or BankConfig()
        self.store = Store(self.cfg.database)
        self.store.seed_demo()
        in_memory = self.cfg.db_path is not None and str(self.cfg.db_path) == ":memory:"
        keys = self.cfg.data_dir / "keys"
        self.as_key = Key.generate() if in_memory else Key.load_or_create(keys / "authorization-server.pem")
        self.receipt_key = Key.generate() if in_memory else Key.load_or_create(keys / "receipts.pem")
        self.registry = registry or StaticRegistry(self.cfg.data_dir, self.cfg.registry_cache_s)
        self.receipts = Receipts(self.store, self.receipt_key)
        # Valet never executes a payment: it instructs the bank's core banking API (the PoC's fictional one here).
        self.core: CoreBanking = core or DemoCore(self.store)
        self.payments = Payments(self.store, self.core, self.receipts, self.cfg.reconcile_after, self.cfg.escalate_after)
        self.payments.blocked = self.denied_for       # the denylist is checked again at execution
        # Customer sign-in: the bank's own IdP over OpenID Connect, or the PoC's demo password (signin is None).
        if signin is None:
            oidc = OidcConfig.from_env(self.cfg.issuer)
            signin = OidcSignIn(oidc) if oidc else None
        self.signin = signin
        # Native mode: tokens issued by the bank's own authorisation server, verified with its published keys.
        self.external_issuers = external_issuers if external_issuers is not None else external_issuers_from_env()
        self.key_binding = self._key_binding_mode()

    # ------------------------------------------------- deployment safety
    def _key_binding_mode(self) -> str:
        """Binding at first use is for demonstrations only: refuse to start if it is on anywhere else."""
        if not self.cfg.allow_first_use_binding:
            return "at_consent"
        demo_core = isinstance(self.core, DemoCore)
        local = bool(self.external_issuers) and all(_loopback(i) for i in self.external_issuers)
        if not (demo_core and local):
            raise RuntimeError(
                "VALET_ALLOW_FIRST_USE_BINDING is for demonstrations only. It needs the fictional payments adapter and "
                "external token issuers on this machine (localhost); this deployment has "
                f"{'a real payments adapter' if not demo_core else 'a non-local token issuer'}. Bind keys at consent "
                "instead (dpop_jkt), or use federated mode.")
        return "first_use_demo_only"

    def readiness(self) -> dict[str, Any]:
        """What a deployment check asserts before go-live (GET /readyz)."""
        reg = self.registry
        return {"status": "ready", "key_binding": self.key_binding,
                "payments_adapter": type(self.core).__name__,
                "adapter_supports_cancel": bool(getattr(self.core, "supports_cancel", False)),
                "registry": {"cache_seconds": self.cfg.registry_cache_s,
                             "available": getattr(reg, "unavailable_since", None) is None},
                "denylist_entries": self.store.one("SELECT COUNT(*) n FROM denylist")["n"],
                "payments_escalated": len(self.payments.escalated()),
                "native_issuers": sorted(self.external_issuers)}

    def native_issuer(self, hint: str | None = None) -> str | None:
        """The token issuer a native-mode grant is bound to: the one named, or the only one configured."""
        if hint and hint in self.external_issuers:
            return hint
        return next(iter(self.external_issuers)) if len(self.external_issuers) == 1 else None

    # ------------------------------------------------- the bank's denylist and stopping a grant
    def deny(self, kind: str, value: str, reason: str) -> None:
        if kind not in ("client_id", "operator", "jkt"):
            raise ValueError("kind is client_id, operator or jkt")
        self.store.x("INSERT OR REPLACE INTO denylist VALUES (?,?,?,?)", kind, value, reason, time.time())

    def undeny(self, kind: str, value: str) -> None:
        self.store.x("DELETE FROM denylist WHERE kind=? AND value=?", kind, value)

    def denied(self, client_id: str, jkt: str | None = None) -> str | None:
        """Why the bank has stopped this agent, operator or key, or None. Read from the database on every call, so a
        change reaches every node sharing it on the next request."""
        rec = self.registry.lookup(client_id)
        for kind, value in (("client_id", client_id), ("operator", rec.operator if rec else None), ("jkt", jkt)):
            if value:
                row = self.store.one("SELECT reason FROM denylist WHERE kind=? AND value=?", kind, value)
                if row:
                    return f"{kind} denylisted by the bank: {row['reason']}"
        return None

    def denied_for(self, grant: dict[str, Any]) -> str | None:
        return self.denied(grant["client_id"], grant.get("jkt"))

    def stop_grant(self, grant_id: str, status: str, why: str) -> dict[str, int]:
        """Pause or revoke: no new calls, every approval not yet used is cancelled, and every payment the bank has not
        accepted is cancelled (design section 5.2). Returns what happened to the payments."""
        self.store.set_status(grant_id, status)
        if status not in ("paused", "revoked"):
            return {"cancelled": 0, "already_paid": 0, "with_bank": 0}
        return self.payments.stop_grant(self.store.grant(grant_id), why)

    # ------------------------------------------------- client authentication
    def authenticate_client(self, form: dict[str, Any], require_trusted: bool = True) -> AgentRecord:
        """private_key_jwt (RFC 7523): the agent signs a short-lived assertion with its registered key."""
        if form.get("client_assertion_type") != JWT_BEARER or not form.get("client_assertion"):
            raise OAuthError("invalid_client", "private_key_jwt client authentication is required", 401)
        assertion = form["client_assertion"]
        try:
            iss = jwt.decode(assertion, options={"verify_signature": False}).get("iss", "")
        except jwt.PyJWTError as e:
            raise OAuthError("invalid_client", f"malformed client assertion: {e}", 401) from e
        rec = self.registry.lookup(iss)
        if not rec:
            raise OAuthError("invalid_client", "unknown agent", 401)
        try:
            claims = verify(assertion, rec.jwk, audience=self.cfg.issuer, options={"require": ["exp", "iat", "jti", "iss", "sub"]})
        except jwt.PyJWTError as e:
            raise OAuthError("invalid_client", f"client assertion rejected: {e}", 401) from e
        if claims["sub"] != rec.client_id or form.get("client_id", rec.client_id) != rec.client_id:
            raise OAuthError("invalid_client", "assertion subject does not match client_id", 401)
        if claims["exp"] - time.time() > 300:
            raise OAuthError("invalid_client", "client assertion lives too long", 401)
        if self.store.seen_jti("ca:" + claims["jti"]):
            raise OAuthError("invalid_client", "client assertion replayed", 401)
        if require_trusted and not self.registry.is_trusted(rec.client_id):
            raise OAuthError("unauthorized_client", "this agent is not verified, so the bank will not connect it", 401)
        return rec

    # --------------------------------------------------------------- tokens
    def issue_access_token(self, grant: dict[str, Any], jkt: str, details: list[dict[str, Any]],
                           approval: str | None = None, exp: float | None = None) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": self.cfg.issuer, "aud": self.cfg.api_audience, "sub": grant["sub"], "client_id": grant["client_id"],
            "grant_id": grant["id"], "authorization_details": details, "cnf": {"jkt": jkt},
            "iat": now, "exp": int(exp) if exp else now + self.cfg.access_ttl, "jti": f"at_{now}_{id(details)}_{time.time_ns()}",
        }
        if approval:
            claims["once"] = True
            claims["approval"] = approval
        return self.as_key.sign(claims, headers={"typ": "at+jwt", "kid": "as-1"})

    def verify_access_token(self, token: str) -> dict[str, Any]:
        """Valet's own tokens (federated mode) or the bank's authorisation server's (native mode)."""
        try:
            iss = jwt.decode(token, options={"verify_signature": False}).get("iss", "")
        except jwt.PyJWTError as e:
            raise OAuthError("invalid_token", f"access token rejected: {e}", 401) from e
        if iss in self.external_issuers:
            try:
                return self.external_issuers[iss].verify(token)
            except TokenRejected as e:
                raise OAuthError("invalid_token", f"access token rejected: {e}", 401) from e
        if iss != self.cfg.issuer:
            raise OAuthError("invalid_token", "access token from an issuer this bank does not accept", 401)
        try:
            return verify(token, self.as_key.jwk, audience=self.cfg.api_audience, issuer=self.cfg.issuer,
                          options={"require": ["exp", "grant_id", "cnf"]})
        except jwt.PyJWTError as e:
            raise OAuthError("invalid_token", f"access token rejected: {e}", 401) from e
