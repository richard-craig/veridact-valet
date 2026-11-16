"""Bank configuration. Everything a pilot bank would set lives here."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from zoneinfo import ZoneInfo

SAST = ZoneInfo("Africa/Johannesburg")


@dataclass
class BankConfig:
    issuer: str = field(default_factory=lambda: os.environ.get("BANK_PUBLIC_URL", "http://localhost:8000"))
    api_audience: str = "marula-api"
    bank_name: str = "Marula Bank"
    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("VALET_DATA", "./data")))
    db_path: Path | None = None              # None: <data_dir>/bank.sqlite; ":memory:" for tests
    session_secret: str = field(default_factory=lambda: os.environ.get("BANK_SESSION_SECRET", "demo-only-secret"))
    # Lifetimes (seconds)
    par_ttl: int = 60
    code_ttl: int = 60
    access_ttl: int = 300
    approval_ttl: int = 300
    ciba_interval: int = 2
    max_pending_approvals: int = 3
    # Refresh tokens rotate. An agent that lost the response may retry with the token it just used for this long,
    # from the same key; after that, reuse pauses the grant. 0 turns the retry off.
    refresh_retry_window: int = 60
    # Payments the bank has not confirmed or declined (a timeout, a crash): ask the bank again after this long. After
    # escalate_after, ask it to cancel-or-confirm; with no answer, the payment goes to the operations queue, still held.
    # Nothing is released on a timer: only the bank's tombstone releases a hold (design section 5.1).
    reconcile_after: int = 30
    escalate_after: int = 900
    # Policy ceilings the bank allows agents (cents)
    max_monthly_limit: int = 5_000_00
    max_grant_days: int = 90
    # Agent trust from the registry is cached this long: withdrawing trust there takes up to this long. The bank's own
    # denylist (agents, operators, keys) has no cache: it is read from the database on every request.
    registry_cache_s: int = 60
    # Consent and approvals need a recent sign-in (seconds). How the customer proves it is the bank IdP's policy.
    step_up_max_age: int = field(default_factory=lambda: int(os.environ.get("STEP_UP_MAX_AGE", "300")))
    # Shared secret for /internal/grants (native mode: the bank's IdP registers consents). Unset: endpoint off.
    # Production: mTLS between the IdP and Valet instead of a shared secret.
    internal_secret: str = field(default_factory=lambda: os.environ.get("VALET_INTERNAL_SECRET", ""))
    # Native mode: a grant is bound to the agent's DPoP key at consent (the IdP passes dpop_jkt in the hand-off ticket
    # or to /internal/grants). Binding on the first API call instead is weaker: demonstrations only. Valet refuses to
    # start with VALET_ALLOW_FIRST_USE_BINDING=1 unless the payments adapter is the fictional one and every external
    # token issuer is on this machine (loopback). It can never be on in a bank deployment.
    allow_first_use_binding: bool = field(
        default_factory=lambda: os.environ.get("VALET_ALLOW_FIRST_USE_BINDING", "") in ("1", "true", "yes"))
    # Consent hand-off from the bank's IdP (native mode, handoff.py). Unset secret: hand-off off.
    handoff_secret: str = field(default_factory=lambda: os.environ.get("VALET_HANDOFF_SECRET", ""))
    # Which IdPs may hand customers over, and the only address each may be returned to:
    # VALET_HANDOFF_IDPS='{"keycloak:marula": "http://localhost:8080/realms/marula/"}'
    handoff_idps: dict = field(default_factory=lambda: json.loads(os.environ.get("VALET_HANDOFF_IDPS", "{}")))

    @property
    def database(self) -> str:
        if self.db_path is not None:
            return str(self.db_path)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return str(self.data_dir / "bank.sqlite")
