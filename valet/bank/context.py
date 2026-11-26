"""Everything the bank's routes share: config, store, keys, registry, receipts, client authentication."""
from __future__ import annotations

import time
from typing import Any

import jwt
from fastapi.responses import JSONResponse

from ..common.crypto import Key, verify
from ..common.signers import KeyRing, jws_kid
from .config import BankConfig
from .core import CoreBanking, DemoCore
from .idp import OidcConfig, OidcSignIn
from .known_assistants import KnownAssistants
from .payments import Payments
from .policy import Policy
from .receipts import Receipts
from .cimd import CimdResolver
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
                 core: CoreBanking | None = None, cimd: CimdResolver | None = None):
        self.cfg = cfg or BankConfig()
        if problems := self.cfg.secret_problems():          # fail closed: never serve HTTPS on demo secrets
            raise RuntimeError("refusing to start: " + "; ".join(problems))
        self.store = Store(self.cfg.database)
        self.store.seed_demo()
        in_memory = self.cfg.db_path is not None and str(self.cfg.db_path) == ":memory:"
        keys = self.cfg.data_dir / "keys"
        # Key rings: the active signer plus previous keys still published for verification (valet/common/signers.py).
        self.as_keys = KeyRing.load("as", keys / "authorization-server.pem", in_memory)
        self.receipt_keys = KeyRing.load("receipts", keys / "receipts.pem", in_memory)
        self.as_key, self.receipt_key = self.as_keys.active, self.receipt_keys.active
        approved = list((self.cfg.cimd or {}).get("approved") or [])
        self.cimd = cimd or (CimdResolver(approved, int(self.cfg.cimd.get("cache_seconds", 300))) if approved else None)
        self.registry = registry or StaticRegistry(self.cfg.data_dir, self.cfg.registry_cache_s, cimd=self.cimd)
        self.receipts = Receipts(self.store, self.receipt_key, self.receipt_keys)
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
        # The bank's policy in force: hashed, kept, and named on every receipt from here on (design section 8.2).
        self.policy = Policy(self.store, self.cfg, self.key_binding)
        self.receipts.policy = self.policy
        # Set by create_app: the Valet decision service, and how the bank's MCP server reaches it.
        self.decision_service: Any = None
        self.decisions: Any = None
        # Lane A: Veridact known-assistant entries for mainstream assistants (known_assistants.py), if configured.
        self.known_assistants: KnownAssistants | None = KnownAssistants.from_env()

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
                "native_issuers": sorted(self.external_issuers),
                "known_assistants": self.known_assistants.readiness() if self.known_assistants else None,
                "cimd": self.cimd.readiness() if self.cimd else None,
                "decision_service": getattr(self.decisions, "transport", None),
                "policy": {**self.policy.ref, "labelled": self.policy.labelled},
                "keys": {"as": self.as_keys.custody(), "receipts": self.receipt_keys.custody()}}

    def assistant(self, client_id: str) -> dict[str, Any] | None:
        """Lane A: what Veridact's known-assistant entry says about this platform client, or None if not covered."""
        known = self.known_assistants
        return known.check(client_id) if known and known.covers(client_id) else None

    def native_issuer(self, hint: str | None = None) -> str | None:
        """The token issuer a native-mode grant is bound to: the one named, or the only one configured."""
        if hint and hint in self.external_issuers:
            return hint
        return next(iter(self.external_issuers)) if len(self.external_issuers) == 1 else None

    # ------------------------------------------------- the bank's denylist and stopping a grant
    def deny(self, kind: str, value: str, reason: str, by: str = "bank operations") -> dict[str, Any]:
        """The emergency stop (design section 9.1). From the next request every call by the agent, operator or key is
        refused. Then, for every grant it covers: approvals not yet used are cancelled, payments the bank has not
        accepted are cancelled (cancel-or-confirm, section 5.1), and a receipt records what was stopped. The grants
        keep their status, so lifting the entry restores access, but anything cancelled must be asked for again.
        Returns the incident summary."""
        if kind not in ("client_id", "operator", "jkt"):
            raise ValueError("kind is client_id, operator or jkt")
        if not value:
            raise ValueError("value is required")
        self.store.x("INSERT OR REPLACE INTO denylist VALUES (?,?,?,?)", kind, value, reason, time.time())
        why = f"{kind} denylisted by the bank: {reason}"
        totals = {"grants": 0, "approvals_cancelled": 0, "cancelled": 0, "already_paid": 0, "with_bank": 0}
        stopped: list[str] = []
        for g in self._grants_covered(kind, value):
            approvals = self.store.cancel_waiting(g["id"])
            payments = self.payments.stop_grant(g, why)
            self.receipts.append(grant_id=g["id"], agent=g["client_id"], customer=g["customer"], action="denylist",
                                 outcome="done", basis="bank", reason=reason, by=by,
                                 denylist={"kind": kind, "value": value},
                                 approvals_cancelled=approvals, payments=payments)
            stopped.append(g["id"])
            totals["grants"] += 1
            totals["approvals_cancelled"] += approvals
            for k, v in payments.items():
                totals[k] += v
        # The bank-level record of the stop itself, naming every grant it reached.
        rec = self.receipts.append(action="denylist_add", outcome="done", basis="bank", reason=reason, by=by,
                                   denylist={"kind": kind, "value": value}, grants=stopped, totals=totals)
        return {"denied": {"kind": kind, "value": value}, "stopped": totals, "grants": stopped,
                "receipt": rec["hash"]}

    def undeny(self, kind: str, value: str, by: str = "bank operations") -> dict[str, Any]:
        removed = self.store.x("DELETE FROM denylist WHERE kind=? AND value=?", kind, value)
        rec = None
        if removed:
            rec = self.receipts.append(action="denylist_remove", outcome="done", basis="bank", by=by,
                                       denylist={"kind": kind, "value": value})
        return {"removed": {"kind": kind, "value": value}, "was_listed": bool(removed),
                "receipt": rec["hash"] if rec else None}

    def _grants_covered(self, kind: str, value: str) -> list[dict[str, Any]]:
        """Live grants (active or paused) that a denylist entry reaches."""
        live = "status IN ('active','paused')"
        if kind == "client_id":
            rows = self.store.q(f"SELECT id FROM grants WHERE client_id=? AND {live}", value)
        elif kind == "jkt":
            rows = self.store.q(f"SELECT id FROM grants WHERE jkt=? AND {live}", value)
        else:   # operator: every agent the registry says that operator runs
            clients = [r["client_id"] for r in self.store.q(f"SELECT DISTINCT client_id FROM grants WHERE {live}")
                       if (rec := self.registry.lookup(r["client_id"])) and rec.operator == value]
            rows = [r for c in clients for r in self.store.q(f"SELECT id FROM grants WHERE client_id=? AND {live}", c)]
        return [g for r in rows if (g := self.store.grant(r["id"])) and g["status"] in ("active", "paused")]

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
            kid = jwt.get_unverified_header(assertion).get("kid")
        except jwt.PyJWTError as e:
            raise OAuthError("invalid_client", f"malformed client assertion: {e}", 401) from e
        rec = self.registry.lookup(iss)
        if not rec:
            raise OAuthError("invalid_client", "unknown agent", 401)
        key = rec.key_for(kid)          # a CIMD agent may publish several keys; the assertion's kid picks one
        if not key:
            raise OAuthError("invalid_client", "the assertion's kid names none of this agent's published keys", 401)
        try:
            claims = verify(assertion, key, audience=self.cfg.issuer, options={"require": ["exp", "iat", "jti", "iss", "sub"]})
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
            "act": {"sub": grant["client_id"]},           # RFC 8693: the agent acts for the customer in "sub"
            "iat": now, "exp": int(exp) if exp else now + self.cfg.access_ttl, "jti": f"at_{now}_{id(details)}_{time.time_ns()}",
        }
        if approval:
            claims["once"] = True
            claims["approval"] = approval
        return self.as_key.sign(claims, headers={"typ": "at+jwt"})

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
        err: jwt.PyJWTError | None = None
        for jwk in self.as_keys.find(jws_kid(token)):     # the signing key, or every key during a rotation
            try:
                return verify(token, jwk, audience=self.cfg.api_audience, issuer=self.cfg.issuer,
                              options={"require": ["exp", "grant_id", "cnf"]})
            except jwt.PyJWTError as e:
                err = e
        raise OAuthError("invalid_token", f"access token rejected: {err}", 401) from err
