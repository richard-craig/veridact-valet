"""
Small, explicit crypto helpers. ES256 (P-256) everywhere the bank signs or chooses the algorithm.

- Keys and JWKs, with RFC 7638 thumbprints (used as DPoP `jkt`).
- Signing and verifying compact JWS/JWT with an algorithm allow-list of exactly ["ES256"].
- One exception, `verify_agent`: an agent's client assertions and Poppy delegations may also be PS384 with an RSA key,
  which Poppy 1.1 (sections 4.1 and 5.2) requires a bank to accept, so agents can have them signed blindly (RFC 9474).
  The key type fixes the algorithm (EC P-256: ES256; RSA, at least 2048 bits: PS384), so neither can stand in for the
  other.
- JSON canonicalisation for hashing (a JCS subset: sorted keys, no whitespace, UTF-8),
  which is exact for the strings, integers and booleans Valet hashes.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

ALGS = ["ES256"]


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_b64u(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return b64u(hashlib.sha256(data).digest())


def digest(obj: Any) -> str:
    """Digest of a JSON object, as used for action digests and receipts."""
    return "sha256:" + hashlib.sha256(canonical(obj)).hexdigest()


def random_id(prefix: str, n: int = 16) -> str:
    return f"{prefix}_{secrets.token_urlsafe(n)}"


class Key:
    """An ES256 key pair with its public JWK and thumbprint."""

    def __init__(self, private: ec.EllipticCurvePrivateKey):
        self.private = private
        self.public = private.public_key()

    @classmethod
    def generate(cls) -> "Key":
        return cls(ec.generate_private_key(ec.SECP256R1()))

    @classmethod
    def load_or_create(cls, path: Path) -> "Key":
        """Demo convenience. In production, agent keys live in KMS, a TPM or an HSM."""
        if path.exists():
            return cls(serialization.load_pem_private_key(path.read_bytes(), password=None))
        k = cls.generate()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        pem = k.private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)   # readable by the service account only
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
        return k

    @property
    def jwk(self) -> dict[str, str]:
        nums = self.public.public_numbers()
        return {"kty": "EC", "crv": "P-256",
                "x": b64u(nums.x.to_bytes(32, "big")), "y": b64u(nums.y.to_bytes(32, "big"))}

    @property
    def thumbprint(self) -> str:
        return jwk_thumbprint(self.jwk)

    def sign(self, claims: dict[str, Any], headers: dict[str, Any] | None = None) -> str:
        return jwt.encode(claims, self.private, algorithm="ES256", headers=headers or {})


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638: SHA-256 over the required members in lexicographic order."""
    members = ("e", "kty", "n") if jwk.get("kty") == "RSA" else ("crv", "kty", "x", "y")
    required = {k: jwk[k] for k in members}
    return sha256_b64u(json.dumps(required, sort_keys=True, separators=(",", ":")))


def public_key_from_jwk(jwk: dict[str, Any]):
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("only EC P-256 keys are accepted")
    return jwt.algorithms.ECAlgorithm.from_jwk(json.dumps({k: jwk[k] for k in ("kty", "crv", "x", "y")}))


RSA_PRIVATE = ("d", "p", "q", "dp", "dq", "qi", "oth")
MIN_RSA_BITS = 2048


def agent_key_alg(jwk: dict[str, Any]) -> str | None:
    """The one algorithm an agent's published key may sign with, or None if Valet doesn't accept the key."""
    if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256" and "d" not in jwk and {"x", "y"} <= set(jwk):
        return "ES256"
    if jwk.get("kty") == "RSA" and {"n", "e"} <= set(jwk) and not any(k in jwk for k in RSA_PRIVATE):
        try:
            bits = len(base64.urlsafe_b64decode(jwk["n"] + "=" * (-len(jwk["n"]) % 4)).lstrip(b"\0")) * 8
        except (ValueError, TypeError):
            return None
        return "PS384" if bits >= MIN_RSA_BITS else None
    return None


def verify_agent(token: str, jwk: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    """Verify an agent's client assertion or delegation: ES256 for a P-256 key, PS384 for an RSA key."""
    alg = agent_key_alg(jwk)
    if alg is None:
        raise jwt.InvalidKeyError("the agent's key is not an accepted EC P-256 or RSA (2048 bits or more) key")
    if alg == "ES256":
        return verify(token, jwk, **kwargs)
    key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps({k: jwk[k] for k in ("kty", "n", "e")}))
    return jwt.decode(token, key, algorithms=["PS384"], **kwargs)


def verify(token: str, jwk: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    """Verify a JWT with an explicit ES256-only allow-list. Raises jwt.PyJWTError on failure."""
    return jwt.decode(token, public_key_from_jwk(jwk), algorithms=ALGS, **kwargs)


def unverified_header(token: str) -> dict[str, Any]:
    return jwt.get_unverified_header(token)
