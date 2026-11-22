"""
Lane A: Veridact known-assistant entries (docs/mcp-gateway-design.md, "Veridact known-assistant entries").

Anthropic, OpenAI, Google and Microsoft will not present Veridact credentials, so Veridact signs a statement ABOUT
each platform: an SD-JWT VC with vct https://veridact.net/vct/known-assistant/v1, and a Token Status List entry that
says valid, withdrawn or suspended. The bank checks both itself, with keys from the attester's JWT VC Issuer Metadata.
Nothing is sent to Veridact about the customer or the call.

The bank's MCP server uses the result three ways:
  admission    a platform client must map to a valid entry, at consent and on every call (via the decision service)
  consent      the verified operator's name ("Claude, operated by Anthropic PBC") replaces the self-asserted one
  kill switch  a suspended or withdrawn entry stops the assistant at every bank on its next status check
An entry never raises an assistant's assurance tier, and its max_level is a ceiling the bank may lower, never raise.

Configured with VALET_KNOWN_ASSISTANTS, a JSON object:
  {"issuer": "https://veridact.example",          the attester's identifier (the iss of everything it signs)
   "fetch": "http://veridact:8100",                optional: where this server reaches it (inside Docker)
   "entries": {"claude": "claude"},                OAuth client id -> entry id
   "cache_seconds": 15}                            how long a status answer is reused (adds to the withdrawal time)
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import time
import zlib
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt

VCT = "https://veridact.net/vct/known-assistant/v1"
STATUS = {0: "valid", 1: "withdrawn", 2: "suspended"}


class EntryInvalid(Exception):
    """The entry or the status list did not verify: treated like no entry at all."""


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


@dataclass
class _Cached:
    value: Any = None
    at: float = 0.0
    error: str | None = None


@dataclass
class KnownAssistants:
    issuer: str
    entries: dict[str, str]
    fetch: str | None = None
    cache_seconds: int = 15
    http: httpx.Client | None = None
    _cache: dict[str, _Cached] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @classmethod
    def from_env(cls) -> "KnownAssistants | None":
        raw = os.environ.get("VALET_KNOWN_ASSISTANTS", "").strip()
        if not raw:
            return None
        c = json.loads(raw)
        return cls(issuer=c["issuer"].rstrip("/"), entries=dict(c.get("entries") or {}),
                   fetch=(c.get("fetch") or "").rstrip("/") or None, cache_seconds=int(c.get("cache_seconds", 15)))

    # ------------------------------------------------------------ the bank's questions
    def covers(self, client_id: str) -> bool:
        return client_id in self.entries

    def entry_url(self, client_id: str) -> str:
        return f"{self.issuer}/known-assistants/{self.entries[client_id]}"

    def check(self, client_id: str) -> dict[str, Any]:
        """What the bank passes to Valet as context.veridact. Never raises: a failure is status 'unavailable'."""
        url = self.entry_url(client_id)
        try:
            claims = self._entry(client_id)
            state = self._status(claims)
            return {"entry": url, "status": state, "operator": claims["operator"].get("name"),
                    "name": claims.get("name"), "max_level": claims.get("max_level"), "vct": VCT,
                    "checked_at": int(time.time())}
        except (EntryInvalid, httpx.HTTPError, KeyError, ValueError, TypeError) as e:
            return {"entry": url, "status": "unavailable", "detail": str(e)[:160], "checked_at": int(time.time())}

    def display_name(self, client_id: str) -> str | None:
        """'Claude, operated by Anthropic PBC', from the last entry that verified."""
        if not self.covers(client_id):
            return None
        c = self._cache.get("entry:" + client_id)
        claims = c.value if c and c.value else None
        if not claims:
            try:
                claims = self._entry(client_id)
            except Exception:              # noqa: BLE001 - a name is cosmetic; admission is checked separately
                return None
        return f"{claims.get('name') or client_id}, operated by {claims['operator']['name']}"

    def readiness(self) -> dict[str, Any]:
        return {"issuer": self.issuer, "cache_seconds": self.cache_seconds,
                "entries": {cid: self.check(cid)["status"] for cid in self.entries}}

    # ------------------------------------------------------------ fetching, with a short cache
    def _url(self, url: str) -> str:
        if self.fetch and url.startswith(self.issuer):
            return self.fetch + url[len(self.issuer):]
        return url

    def _get(self, url: str) -> httpx.Response:
        if not url.startswith(self.issuer):
            raise EntryInvalid("artefact outside the attester's own URL")
        r = (self.http or httpx.Client(timeout=3)).get(self._url(url))
        r.raise_for_status()
        return r

    def _cached(self, key: str, load) -> Any:
        """A cached value, refreshed after cache_seconds. If the refresh fails, the last good value is used for one
        more period, then the failure is the answer (payments fail closed on it)."""
        now = time.time()
        with self._lock:
            c = self._cache.setdefault(key, _Cached())
            if c.value is not None and now - c.at < self.cache_seconds:
                return c.value
        try:
            value = load()
        except Exception as e:
            with self._lock:
                c.error = str(e)
                if c.value is not None and now - c.at < 2 * self.cache_seconds:
                    return c.value
            raise
        with self._lock:
            c.value, c.at, c.error = value, now, None
        return value

    def _keys(self) -> dict[str, Any]:
        def load():
            meta = self._get(self.issuer + "/.well-known/jwt-vc-issuer").json()
            if meta.get("issuer", "").rstrip("/") != self.issuer:
                raise EntryInvalid("issuer metadata names a different issuer")
            return {k["kid"]: jwt.PyJWK({x: k[x] for x in ("kty", "crv", "x", "y")}, algorithm="ES256").key
                    for k in (meta.get("jwks") or {}).get("keys", []) if k.get("kid")}
        return self._cached("keys", load)

    def _verify(self, token: str, typ: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as e:
            raise EntryInvalid(f"unreadable {typ}") from e
        if header.get("typ") != typ or header.get("alg") != "ES256":
            raise EntryInvalid(f"expected typ {typ} and ES256")
        key = self._keys().get(header.get("kid"))
        if key is None:
            raise EntryInvalid("signed with a key the attester does not publish")
        try:
            return jwt.decode(token, key, algorithms=["ES256"], issuer=self.issuer, leeway=30,
                              options={"require": ["iss", "iat", "exp"], "verify_aud": False})
        except jwt.PyJWTError as e:
            raise EntryInvalid(f"{typ} rejected: {e}") from e

    def _entry(self, client_id: str) -> dict[str, Any]:
        def load():
            return parse_sd_jwt_vc(self._get(self.entry_url(client_id)).text, self._verify, client_id)
        return self._cached("entry:" + client_id, load)

    def _status(self, claims: dict[str, Any]) -> str:
        ref = (claims.get("status") or {}).get("status_list") or {}
        uri, idx = ref.get("uri"), ref.get("idx")
        if not isinstance(uri, str) or not isinstance(idx, int):
            raise EntryInvalid("entry has no status list reference")

        def load():
            payload = self._verify(self._get(uri).text, "statuslist+jwt")
            if payload.get("sub") != uri:
                raise EntryInvalid("status list token is for a different list")
            return payload["status_list"]
        sl = self._cached("status:" + uri, load)
        bits = int(sl.get("bits", 1))
        raw = zlib.decompress(_b64d(sl["lst"]))
        byte, shift = divmod(idx * bits, 8)
        if byte >= len(raw):
            raise EntryInvalid("status index outside the list")
        value = (raw[byte] >> shift) & ((1 << bits) - 1)
        return STATUS.get(value, "withdrawn")          # an unknown value is never "valid"


def parse_sd_jwt_vc(compact: str, verify, client_id: str) -> dict[str, Any]:
    """Verify an SD-JWT VC known-assistant entry and return its claims with every disclosure applied."""
    parts = compact.strip().split("~")
    if len(parts) < 2:
        raise EntryInvalid("not an SD-JWT (no '~')")
    issuer_jwt, disclosures = parts[0], [p for p in parts[1:] if p]
    if disclosures and "." in disclosures[-1]:
        raise EntryInvalid("an entry is never presented with a key binding JWT")
    claims = verify(issuer_jwt, "dc+sd-jwt")
    if claims.get("vct") != VCT:
        raise EntryInvalid("not a known-assistant entry")
    if claims.get("sub") != client_id and client_id not in (claims.get("client_metadata_urls") or []):
        raise EntryInvalid("the entry is about a different client")
    digests = set(claims.pop("_sd", []) or [])
    if claims.pop("_sd_alg", "sha-256") != "sha-256":
        raise EntryInvalid("unsupported _sd_alg")
    for d in disclosures:
        h = _b64e(hashlib.sha256(d.encode("ascii")).digest())
        if h not in digests:
            raise EntryInvalid("a disclosure does not match the signed digests")
        try:
            _salt, name, value = json.loads(_b64d(d))
        except ValueError as e:
            raise EntryInvalid("malformed disclosure") from e
        if name in claims or name in ("_sd", "_sd_alg", "iss", "vct", "sub", "status"):
            raise EntryInvalid(f"disclosure may not set {name!r}")
        claims[name] = value
    if not isinstance(claims.get("operator"), dict) or not claims["operator"].get("name"):
        raise EntryInvalid("entry names no operator")
    return claims
