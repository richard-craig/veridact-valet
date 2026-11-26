"""
CIMD: OAuth Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document), as Valet's baseline agent
check. This is how a Personal Agent Protocol (Poppy) agent identifies itself to a company it has never met.

An agent's client_id is an HTTPS URL. The document at that URL names the agent, its redirect URIs and its public keys
(`jwks` or `jwks_uri`), and its `client_id` must equal the URL. Holding the domain proves only who runs the agent's
website. It says nothing about the operator's licensing, conduct or limits. So Valet treats CIMD as the entry tier:

    tier       how the bank knows the agent                            highest access level
    cimd       an approved domain serves its client metadata          Approved payer (every payment approved in the app)
    veridact   a Veridact credential, on top of the same CIMD URL      Bill payer

A bank admits CIMD agents only from the domains it approves (VALET_CIMD_APPROVED). Valet never fetches a document
from a domain that is not on the list, so a client_id can't make the bank call an arbitrary address. The list is
checked on every call, not only at consent: taking a domain off it stops that agent's live grants on its next request.
That is the opposite of an allow-list that only blocks new connections.

Configured with VALET_CIMD (BankConfig.cimd), a JSON object. Unset or empty: CIMD client ids are refused.
  {"approved": ["agent.example", "*.agents.example"],   domains whose agents may connect ("*" admits any: not advised)
   "cache_seconds": 300}                                 how long a document is reused (the allow-list is never cached)
"""
from __future__ import annotations

import ipaddress
import json
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlsplit

import httpx

MAX_BYTES = 5 * 1024                 # the draft's recommended ceiling for a metadata document
FORBIDDEN_AUTH = ("client_secret_basic", "client_secret_post", "client_secret_jwt", "none")


class CimdInvalid(Exception):
    """The client_id is not a usable metadata document URL, or the document failed a check."""


def is_cimd_client_id(client_id: str) -> bool:
    """The draft's rules for a client_id URL: https, a host, a path, no userinfo, fragment, dot segments or query."""
    if not isinstance(client_id, str) or not client_id.startswith("https://"):
        return False
    p = urlsplit(client_id)
    segments = p.path.split("/")
    return bool(p.hostname and p.path not in ("", "/") and not p.username and not p.password and not p.fragment
                and not p.query and "." not in segments and ".." not in segments)


def host_of(client_id: str) -> str:
    return (urlsplit(client_id).hostname or "").lower()


def approved(host: str, patterns: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for pat in patterns:
        pat = pat.lower().strip()
        if pat == "*" or pat == host or (pat.startswith("*.") and host.endswith(pat[1:]) and host != pat[2:]):
            return True
    return False


def public_address(host: str) -> None:
    """Refuse a host that resolves to a private, loopback, link-local or otherwise internal address."""
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except OSError as e:
        raise CimdInvalid(f"cannot resolve {host}") from e
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise CimdInvalid(f"{host} resolves to a non-public address")


@dataclass
class _Doc:
    meta: dict[str, Any]
    jwks: list[dict[str, Any]]
    at: float


@dataclass
class CimdResolver:
    approved_domains: list[str]
    cache_seconds: int = 300
    http: httpx.Client | None = None
    check_address: Callable[[str], None] = public_address
    last_error: str | None = None
    _docs: dict[str, _Doc] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    # ------------------------------------------------------------ the bank's questions
    def covers(self, client_id: str) -> bool:
        """A CIMD client_id from a domain the bank approves, as of now."""
        return is_cimd_client_id(client_id) and approved(host_of(client_id), self.approved_domains)

    def resolve(self, client_id: str) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
        """The agent's metadata and public keys, or None if it is not an approved CIMD client or its document fails.
        A document already read is still returned after its domain leaves the list, so the bank's screens can name the
        agent whose grants it stopped. Trust is decided by covers(), never by this."""
        if not is_cimd_client_id(client_id):
            return None
        now = time.time()
        with self._lock:
            doc = self._docs.get(client_id)
        fresh = doc and now - doc.at < self.cache_seconds
        if fresh or (doc and not self.covers(client_id)):
            return doc.meta, doc.jwks
        if not self.covers(client_id):
            return None
        try:
            meta, jwks = self._fetch(client_id)
        except (CimdInvalid, httpx.HTTPError, ValueError) as e:
            if doc and now - doc.at < 2 * self.cache_seconds:     # one more period on the last good copy
                return doc.meta, doc.jwks
            self.last_error = f"{client_id}: {e}"
            return None
        with self._lock:
            self._docs[client_id] = _Doc(meta, jwks, now)
        return meta, jwks

    # ------------------------------------------------------------ fetching
    def _get(self, url: str) -> bytes:
        host = host_of(url)
        self.check_address(host)
        client = self.http or httpx.Client(timeout=3, follow_redirects=False)
        with client.stream("GET", url, headers={"Accept": "application/json"}) as r:
            if r.status_code != 200:                     # redirects are refused: the document lives at its own URL
                raise CimdInvalid(f"{url} answered {r.status_code}")
            body = b""
            for chunk in r.iter_bytes():
                body += chunk
                if len(body) > MAX_BYTES:
                    raise CimdInvalid(f"{url} is larger than {MAX_BYTES} bytes")
        return body

    def _fetch(self, client_id: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        meta = json.loads(self._get(client_id))
        if not isinstance(meta, dict):
            raise CimdInvalid("the metadata document is not a JSON object")
        if meta.get("client_id") != client_id:
            raise CimdInvalid("the document's client_id is not its own URL")
        if meta.get("token_endpoint_auth_method", "private_key_jwt") != "private_key_jwt":
            raise CimdInvalid("Valet agents authenticate with private_key_jwt")
        if any(k.startswith("client_secret") for k in meta):
            raise CimdInvalid("a metadata document must not carry a client secret")
        redirects = meta.get("redirect_uris") or []
        if not isinstance(redirects, list) or not all(isinstance(u, str) and u.startswith("https://") for u in redirects):
            raise CimdInvalid("redirect_uris must be a list of https URLs")
        if "jwks" in meta:
            jwks = meta["jwks"]
        elif isinstance(meta.get("jwks_uri"), str):
            uri = meta["jwks_uri"]
            # Keys come from the same origin as the document, so the approved domain is the one vouching for them.
            if not uri.startswith("https://") or host_of(uri) != host_of(client_id):
                raise CimdInvalid("jwks_uri must be https on the client's own host")
            jwks = json.loads(self._get(uri))
        else:
            raise CimdInvalid("the document names no public keys (jwks or jwks_uri)")
        keys = [k for k in (jwks or {}).get("keys", []) if isinstance(k, dict) and k.get("kty") == "EC"
                and k.get("crv") == "P-256" and "d" not in k]
        if not keys:
            raise CimdInvalid("no usable ES256 public key")
        return meta, keys

    def readiness(self) -> dict[str, Any]:
        return {"approved": list(self.approved_domains), "cache_seconds": self.cache_seconds,
                "documents_cached": len(self._docs), "admits_any_domain": "*" in self.approved_domains}
