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
    # Policy ceilings the bank allows agents (cents)
    max_monthly_limit: int = 5_000_00
    max_grant_days: int = 90
    registry_cache_s: int = 60
    # Consent and approvals need a recent sign-in (seconds). How the customer proves it is the bank IdP's policy.
    step_up_max_age: int = field(default_factory=lambda: int(os.environ.get("STEP_UP_MAX_AGE", "300")))
    # Shared secret for /internal/grants (native mode: the bank's IdP registers consents). Unset: endpoint off.
    # Production: mTLS between the IdP and Valet instead of a shared secret.
    internal_secret: str = field(default_factory=lambda: os.environ.get("VALET_INTERNAL_SECRET", ""))
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
