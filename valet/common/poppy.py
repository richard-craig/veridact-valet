"""
Personal Agent Protocol (Poppy) pieces Valet uses: the Session header and its delegated keys (Poppy 1.1, section 5.2).

Valet uses a Poppy Session only as **evidence**: the Session ID goes into the bank's receipts, so a dispute can follow
one continuous interaction across API calls, MCP calls and approvals. A Session never grants access; the access token
and the mandate do.

A Session JWT is signed for one request by a *delegated* key. A delegation, signed by a key from the agent's own
client metadata (its `jwks_uri`, here the agent's registry key), names that delegated key in `cnf.jwk`:

    Poppy-Session: <session JWT>     header: typ poppy-session+jwt, alg ES256, kid = thumbprint(delegated key),
                                             poppy_dlg = <delegation JWT>
                                     claims: iss (client_id), aud, sid, sub, htm, htu, iat, jti, ath (with a token)
    delegation JWT                   header: typ poppy-delegation+jwt, alg ES256, kid = thumbprint(agent key)
                                     claims: iss (client_id), cnf.jwk, iat, exp (at most 24 hours after iat)
"""
from __future__ import annotations

import contextvars
import time
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

import jwt

from .crypto import Key, jwk_thumbprint, random_id, sha256_b64u, unverified_header, verify

SESSION_TYP = "poppy-session+jwt"
DELEGATION_TYP = "poppy-delegation+jwt"
MAX_DELEGATION_S = 24 * 3600
MAX_AGE_S = 300

# The Poppy Session of the request being handled, if it carried one; receipts read it (valet/bank/receipts.py).
current_session: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar("poppy_session", default=None)


def _htu(url: str) -> str:
    """The request URL without query or fragment, as in a DPoP proof."""
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path, "", ""))


# ------------------------------------------------------------------ agent side (SDK, demo and tests)
def make_delegation(agent_key: Key, client_id: str, delegated: Key, lifetime: int = 3600) -> str:
    now = int(time.time())
    return agent_key.sign({"iss": client_id, "cnf": {"jwk": delegated.jwk}, "iat": now, "exp": now + lifetime},
                          headers={"typ": DELEGATION_TYP, "kid": agent_key.thumbprint})


def make_session(delegated: Key, delegation: str, client_id: str, audience: str, sid: str, user_id: str,
                 method: str, url: str, access_token: str | None = None) -> str:
    claims = {"iss": client_id, "aud": audience, "sid": sid, "sub": user_id, "htm": method.upper(), "htu": _htu(url),
              "iat": int(time.time()), "jti": random_id("pj")}
    if access_token:
        claims["ath"] = sha256_b64u(access_token)
    return delegated.sign(claims, headers={"typ": SESSION_TYP, "kid": delegated.thumbprint, "poppy_dlg": delegation})


# ------------------------------------------------------------------ bank side
def read_session(value: str, agent_jwk: Callable[[str], dict[str, Any] | None], audience: str, method: str, url: str,
                 access_token: str | None = None) -> dict[str, Any]:
    """
    Read a Poppy-Session header for the receipt. Always returns what it could read, with `verified` saying whether
    every check passed and `why` naming the first that failed. Never raises: a bad header is recorded, not trusted.
    """
    out: dict[str, Any] = {"protocol": "poppy", "verified": False}
    try:
        head = unverified_header(value)
        body = jwt.decode(value, options={"verify_signature": False})
        out.update({k: body[k] for k in ("sid", "iss", "sub", "agent_id") if isinstance(body.get(k), str)})
        if head.get("typ") != SESSION_TYP or head.get("alg") != "ES256":
            out["why"] = "session_typ_or_alg"
            return out
        dlg = head.get("poppy_dlg")
        if not isinstance(dlg, str):
            out["why"] = "no_delegation"
            return out
        dh = unverified_header(dlg)
        jwk = agent_jwk(body.get("iss", ""))
        if not jwk:
            out["why"] = "agent_key_unknown"
            return out
        if dh.get("typ") != DELEGATION_TYP or dh.get("kid") != jwk_thumbprint(jwk):
            out["why"] = "delegation_header"
            return out
        d = verify(dlg, jwk, options={"require": ["iat", "exp"]})
        if d.get("iss") != body.get("iss") or d["exp"] - d["iat"] > MAX_DELEGATION_S:
            out["why"] = "delegation_claims"
            return out
        delegated = (d.get("cnf") or {}).get("jwk")
        if not delegated or head.get("kid") != jwk_thumbprint(delegated):
            out["why"] = "delegated_key"
            return out
        s = verify(value, delegated, audience=audience, options={"require": ["iat"]})
        if s.get("htm") != method.upper() or s.get("htu") != _htu(url):
            out["why"] = "htm_htu"
        elif abs(time.time() - s["iat"]) > MAX_AGE_S:
            out["why"] = "stale"
        elif access_token and s.get("ath") != sha256_b64u(access_token):
            out["why"] = "ath"
        else:
            out["verified"] = True
            out["delegated_key"] = head["kid"]
    except (jwt.PyJWTError, ValueError, KeyError, TypeError) as e:
        out["why"] = type(e).__name__
    return out
