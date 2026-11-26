"""
Agent identity, behind one interface.

The PoC uses StaticRegistry: a bank-controlled trust file naming each agent's operator and
whether it is verified, plus the public keys agents publish. In production, VeridactRegistry
replaces it: the operator name and tier come from the agent's Veridact credential, and trust
from Veridact's status lists and revocation push.

Agents can also identify themselves with a CIMD client_id (cimd.py): an HTTPS URL serving their
metadata and keys. That is the baseline tier. A CIMD agent the trust file also marks verified
(standing in for a Veridact credential about the same URL) is on the Veridact tier.

    tier        trusted when                                   highest level
    veridact    verified in the registry                       Bill payer
    platform    an AI platform the bank allowlisted            set by the MCP gateway (bearer tier: every payment approved)
    cimd        its domain is on the bank's approved list      Approved payer
    unverified  never                                          none
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .cimd import host_of, is_cimd_client_id


@dataclass
class AgentRecord:
    client_id: str
    name: str
    operator: str
    verified: bool
    jwk: dict[str, Any]
    redirect_uris: list[str] = field(default_factory=list)
    platform: bool = False        # an AI platform's OAuth client (e.g. Claude, ChatGPT) reaching the bank via the MCP gateway
    jwks: list[dict[str, Any]] = field(default_factory=list)    # every key the agent publishes (CIMD may list several)
    cimd: bool = False            # identified by a client ID metadata document; trust also needs its domain approved

    @property
    def tier(self) -> str:
        if self.platform:
            return "platform"
        if self.verified:
            return "veridact"
        return "cimd" if self.cimd else "unverified"

    @property
    def ceiling(self) -> str | None:
        """The highest access level this agent's tier may hold. None: only the bank's own policy limits it (platform
        clients are capped by the MCP gateway instead)."""
        return "approved_payer" if self.tier in ("cimd", "unverified") else None

    def key_for(self, kid: str | None) -> dict[str, Any] | None:
        """The public key a signature names, by kid or JWK thumbprint; the only key when there is just one."""
        from ..common.crypto import jwk_thumbprint
        keys = self.jwks or ([self.jwk] if self.jwk else [])
        if kid:
            for k in keys:
                if k.get("kid") == kid or jwk_thumbprint(k) == kid:
                    return k
        return keys[0] if len(keys) == 1 else None


class RegistryUnavailable(Exception):
    """The registry could not be read and the bank's rule says not to rely on the last copy for this request."""


class AgentRegistry(Protocol):
    def lookup(self, client_id: str) -> AgentRecord | None: ...
    def is_trusted(self, client_id: str, for_payment: bool = False) -> bool: ...


class StaticRegistry:
    """trust.json (bank-controlled) + agents/<client_id>.json (each agent's published public key)."""

    def __init__(self, data_dir: Path, cache_s: int = 60, cimd=None):
        self.dir = data_dir
        self.cimd = cimd                        # a CimdResolver (cimd.py), or None: CIMD client ids are not accepted
        self.cache_s = cache_s
        self._cache: dict[str, Any] = {}
        self._loaded = 0.0                      # when the last good copy was read
        self.unavailable_since: float | None = None
        self._overrides: dict[str, bool] = {}   # bank or Veridact revocation, for the demo

    def _load(self) -> dict[str, Any]:
        """The trust list, refreshed when the cache is older than `cache_s`. If the refresh fails, the last good copy
        is kept and the registry is marked unavailable: payments fail closed at once, reads may use the last copy
        for one more cache period (design section 9)."""
        if time.time() - self._loaded > self.cache_s or not self._loaded:
            trust_file = self.dir / "trust.json"
            try:
                self._cache = json.loads(trust_file.read_text()) if trust_file.exists() else {}
                self._loaded, self.unavailable_since = time.time(), None
            except (OSError, ValueError):
                self.unavailable_since = self.unavailable_since or time.time()
        return self._cache

    def check_available(self, for_payment: bool) -> None:
        self._load()
        if self.unavailable_since is None:
            return
        if for_payment or time.time() - self._loaded > 2 * self.cache_s or not self._loaded:
            raise RegistryUnavailable("the agent registry cannot be reached")

    def lookup(self, client_id: str) -> AgentRecord | None:
        entry = self._load().get(client_id)
        key_file = self.dir / "agents" / f"{client_id}.json"
        if entry and entry.get("platform"):
            # Platform clients hold no agent key: they authenticate to the bank's IdP and send bearer tokens to the
            # MCP gateway, which caps what they can do (bearer tier: every payment approved in the bank app).
            return AgentRecord(client_id=client_id, name=entry["name"], operator=entry["operator"],
                               verified=bool(entry.get("verified")), jwk={}, platform=True)
        if self.cimd is not None and is_cimd_client_id(client_id):
            return self._cimd_record(client_id, entry)
        if not entry or "/" in client_id or not key_file.exists():
            return None
        pub = json.loads(key_file.read_text())
        return AgentRecord(client_id=client_id, name=entry["name"], operator=entry["operator"],
                           verified=bool(entry.get("verified")), jwk=pub["jwk"],
                           redirect_uris=pub.get("redirect_uris", []))

    def _cimd_record(self, client_id: str, entry: dict[str, Any] | None) -> AgentRecord | None:
        doc = self.cimd.resolve(client_id)
        if not doc:
            return None
        meta, keys = doc
        entry, host = entry or {}, host_of(client_id)
        # The operator is the domain that served the document, which the bank checked; client_name is the agent's own
        # claim. A trust entry (in production, the agent's Veridact credential about this URL) overrides both.
        return AgentRecord(client_id=client_id, name=entry.get("name") or str(meta.get("client_name") or host)[:60],
                           operator=entry.get("operator") or host, verified=bool(entry.get("verified")),
                           jwk=keys[0], jwks=keys, redirect_uris=list(meta.get("redirect_uris") or []), cimd=True)

    def is_trusted(self, client_id: str, for_payment: bool = False) -> bool:
        self.check_available(for_payment)
        if client_id in self._overrides:
            return self._overrides[client_id]
        rec = self.lookup(client_id)
        if rec and rec.cimd and not (self.cimd and self.cimd.covers(client_id)):
            return False            # the bank took the domain off its approved list: this stops live grants too
        # Veridact-verified agents, AI platforms the bank has allowlisted (capped at the bearer tier by the gateway),
        # and CIMD agents from approved domains (capped at Approved payer)
        return bool(rec and (rec.verified or rec.platform or rec.cimd))

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
    "claude": {"name": "Claude", "operator": "Anthropic, through Marula Bank's MCP gateway", "verified": False,
               "platform": True},
    "chatgpt": {"name": "ChatGPT", "operator": "OpenAI, through Marula Bank's MCP gateway", "verified": False,
                "platform": True},
}
