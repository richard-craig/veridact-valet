"""
Agent identity, behind one interface.

The PoC uses StaticRegistry: a bank-controlled trust file naming each agent's operator and
whether it is verified, plus the public keys agents publish. In production, VeridactRegistry
replaces it: the operator name and tier come from the agent's Veridact credential, and trust
from Veridact's status lists and revocation push.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


@dataclass
class AgentRecord:
    client_id: str
    name: str
    operator: str
    verified: bool
    jwk: dict[str, Any]
    redirect_uris: list[str] = field(default_factory=list)


class AgentRegistry(Protocol):
    def lookup(self, client_id: str) -> AgentRecord | None: ...
    def is_trusted(self, client_id: str) -> bool: ...


class StaticRegistry:
    """trust.json (bank-controlled) + agents/<client_id>.json (each agent's published public key)."""

    def __init__(self, data_dir: Path, cache_s: int = 60):
        self.dir = data_dir
        self.cache_s = cache_s
        self._cache: dict[str, Any] = {}
        self._loaded = 0.0
        self._overrides: dict[str, bool] = {}   # bank or Veridact revocation, for the demo

    def _load(self) -> dict[str, Any]:
        if time.time() - self._loaded > self.cache_s or not self._cache:
            trust_file = self.dir / "trust.json"
            self._cache = json.loads(trust_file.read_text()) if trust_file.exists() else {}
            self._loaded = time.time()
        return self._cache

    def lookup(self, client_id: str) -> AgentRecord | None:
        entry = self._load().get(client_id)
        key_file = self.dir / "agents" / f"{client_id}.json"
        if not entry or not key_file.exists():
            return None
        pub = json.loads(key_file.read_text())
        return AgentRecord(client_id=client_id, name=entry["name"], operator=entry["operator"],
                           verified=bool(entry.get("verified")), jwk=pub["jwk"],
                           redirect_uris=pub.get("redirect_uris", []))

    def is_trusted(self, client_id: str) -> bool:
        if client_id in self._overrides:
            return self._overrides[client_id]
        rec = self.lookup(client_id)
        return bool(rec and rec.verified)

    def set_trust(self, client_id: str, trusted: bool) -> None:
        """Simulates the bank, or Veridact, withdrawing trust in an agent operator."""
        self._overrides[client_id] = trusted


def write_trust_file(data_dir: Path, entries: dict[str, dict[str, Any]]) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "trust.json").write_text(json.dumps(entries, indent=2))


def publish_agent_key(data_dir: Path, client_id: str, jwk: dict[str, Any], redirect_uris: list[str]) -> None:
    (data_dir / "agents").mkdir(parents=True, exist_ok=True)
    (data_dir / "agents" / f"{client_id}.json").write_text(json.dumps({"jwk": jwk, "redirect_uris": redirect_uris}, indent=2))


DEFAULT_TRUST = {
    "kaya": {"name": "Kaya", "operator": "Kaya Labs (Pty) Ltd", "verified": True},
    "copycat": {"name": "Kaya", "operator": "Unknown operator", "verified": False},
}
