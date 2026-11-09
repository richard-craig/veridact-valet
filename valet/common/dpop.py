"""
DPoP (RFC 9449): proofs that bind a token to the agent's private key.

The agent signs a fresh proof for every request: the HTTP method, the URL, a unique id,
the time, and (when presenting an access token) a hash of that token. The server checks
all of it and returns the key's thumbprint, which must equal the token's `cnf.jkt`.
"""
from __future__ import annotations

import time
from typing import Any, Callable

import jwt

from .crypto import Key, jwk_thumbprint, random_id, sha256_b64u, verify

MAX_AGE_S = 60


def make_proof(key: Key, method: str, url: str, access_token: str | None = None) -> str:
    claims: dict[str, Any] = {"jti": random_id("dp"), "htm": method.upper(), "htu": url.split("?")[0],
                              "iat": int(time.time())}
    if access_token:
        claims["ath"] = sha256_b64u(access_token)
    return key.sign(claims, headers={"typ": "dpop+jwt", "jwk": key.jwk})


class DPoPError(Exception):
    pass


def check_proof(proof: str | None, method: str, url: str, seen_jti: Callable[[str], bool],
                access_token: str | None = None) -> str:
    """Validate a DPoP proof and return the JWK thumbprint of its key.

    `seen_jti(jti)` must record the jti and return True if it was already used.
    """
    if not proof:
        raise DPoPError("missing DPoP proof")
    try:
        header = jwt.get_unverified_header(proof)
    except jwt.PyJWTError as e:
        raise DPoPError(f"malformed proof: {e}") from e
    if header.get("typ") != "dpop+jwt" or header.get("alg") != "ES256" or "jwk" not in header:
        raise DPoPError("proof must be typ dpop+jwt, alg ES256, with an embedded jwk")
    if any(k in header["jwk"] for k in ("d", "p", "q")):
        raise DPoPError("proof jwk must be a public key")
    try:
        claims = verify(proof, header["jwk"], options={"verify_aud": False, "require": ["jti", "htm", "htu", "iat"]})
    except (jwt.PyJWTError, ValueError) as e:
        raise DPoPError(f"bad proof signature: {e}") from e
    if claims["htm"] != method.upper():
        raise DPoPError("htm does not match the request method")
    if claims["htu"] != url.split("?")[0]:
        raise DPoPError("htu does not match the request URL")
    if abs(time.time() - claims["iat"]) > MAX_AGE_S:
        raise DPoPError("proof is too old or from the future")
    if access_token is not None and claims.get("ath") != sha256_b64u(access_token):
        raise DPoPError("ath does not match the access token")
    if seen_jti(claims["jti"]):
        raise DPoPError("proof has been used before")
    return jwk_thumbprint(header["jwk"])
