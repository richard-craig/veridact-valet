"""
The bank's policy in force: what every decision was checked against, besides the mandate (design section 8.2).

A receipt names the mandate and its version: what the customer allowed. A dispute also needs the rules the bank
applied on top: its ceilings, step-up age, approval rules, lifetimes and key-binding mode, and the version of the
Valet profile (check order, error codes, access levels). This module turns those settings into one canonical policy
document, hashes it, and keeps every document the deployment has run with. Every receipt carries

    "policy": {"version": "<the bank's change reference>", "hash": "sha256:..."}

The hash is inside the signed, hash-chained receipt, so the policy a decision was made under cannot be swapped
afterwards; the stored document can be checked against the hash at any time (`verify`).

`version` is the bank's own change-management reference (VALET_POLICY_VERSION, e.g. a change ticket). If the bank
does not set one, the version is "unlabelled-" plus the start of the hash, and `GET /readyz` reports
`labelled: false`, so a go-live check can refuse it. The hash, not the label, is what identifies the policy: a label
reused for different settings gives a different hash, and both are kept.
"""
from __future__ import annotations

import json
import time
from typing import Any

from ..common.crypto import digest
from . import levels as L
from .config import BankConfig
from .store import Store

# The Valet profile this code implements: check order, error codes, access levels, approval rules, receipt format.
PROFILE_VERSION = "valet-profile/0.7"

SCHEMA = """
CREATE TABLE IF NOT EXISTS policies (hash TEXT, version TEXT, document TEXT, first_used REAL,
    PRIMARY KEY (hash, version));
"""


def policy_document(cfg: BankConfig, key_binding: str) -> dict[str, Any]:
    """Every setting that changes what an agent may do or how a decision is made. Strings and integers only, so the
    canonical hash is exact."""
    return {
        "profile": PROFILE_VERSION,
        "access_levels": {k: {"title": v["title"], "summary": v["summary"], "never": list(v["never"])}
                          for k, v in L.LEVELS.items()},
        "monthly_limit_choices_cents": list(L.MONTHLY_CHOICES),
        "ceilings": {"max_monthly_limit_cents": int(cfg.max_monthly_limit), "max_grant_days": int(cfg.max_grant_days)},
        "authentication": {"step_up_max_age_s": int(cfg.step_up_max_age), "key_binding": key_binding},
        "approvals": {"ttl_s": int(cfg.approval_ttl), "max_pending": int(cfg.max_pending_approvals)},
        "tokens": {"access_ttl_s": int(cfg.access_ttl), "refresh_retry_window_s": int(cfg.refresh_retry_window)},
        "payments": {"reconcile_after_s": int(cfg.reconcile_after), "escalate_after_s": int(cfg.escalate_after)},
        "registry": {"cache_s": int(cfg.registry_cache_s)},
    }


class Policy:
    """The policy in force for this process, and every policy this deployment has used."""

    def __init__(self, store: Store, cfg: BankConfig, key_binding: str):
        self.store = store
        store.db.executescript(SCHEMA)
        self.document = policy_document(cfg, key_binding)
        self.hash = digest(self.document)
        self.labelled = bool(cfg.policy_version)
        self.version = cfg.policy_version or "unlabelled-" + self.hash.split(":", 1)[1][:12]
        store.x("INSERT OR IGNORE INTO policies VALUES (?,?,?,?)", self.hash, self.version,
                json.dumps(self.document), time.time())

    @property
    def ref(self) -> dict[str, str]:
        """What goes on every receipt."""
        return {"version": self.version, "hash": self.hash}

    def get(self, policy_hash: str) -> dict[str, Any] | None:
        """The exact policy document a receipt names, for a dispute or an evidence pack."""
        row = self.store.one("SELECT version, document FROM policies WHERE hash=? ORDER BY first_used LIMIT 1", policy_hash)
        return {"version": row["version"], "hash": policy_hash, "document": json.loads(row["document"])} if row else None

    def history(self) -> list[dict[str, Any]]:
        return [{"version": r["version"], "hash": r["hash"], "first_used": int(r["first_used"])}
                for r in self.store.q("SELECT hash, version, first_used FROM policies ORDER BY first_used")]

    @staticmethod
    def verify(entry: dict[str, Any]) -> bool:
        """Does a stored policy document still match the hash the receipts carry?"""
        return digest(entry["document"]) == entry["hash"]
