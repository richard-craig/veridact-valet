"""
Where the bank's signing keys live, and how they rotate (docs/technical-design.md section 21, Key and secrets management).

Valet signs three things with keys the bank owns: access tokens (`as`), receipts (`receipts`) and consent events
(`consent-events`). Each purpose has a **key ring**: one active key that signs, and previous keys that are still
published so that tokens, receipts and evidence packs they signed keep verifying.

A key is named by a URI, so the same code runs on a laptop, in Azure and in AWS:

    file:/var/lib/valet/keys/receipts.pem                                  demo and tests: a PEM file (mode 0600)
    azure-kv:https://<vault>.vault.azure.net/keys/<name>[/<version>]      Azure Key Vault or Managed HSM (EC P-256)
    aws-kms:<key id, alias or ARN>                                         AWS KMS (ECC_NIST_P256, SIGN_VERIFY)

With a cloud key the private key never leaves the vault: Valet sends a SHA-256 digest and receives the signature.
On-premises HSMs over PKCS#11 follow the same interface (design; see the technical design).

Configuration, per purpose (`AS`, `RECEIPTS`, `CONSENT_EVENTS`):

    VALET_KEY_RECEIPTS=azure-kv:https://marula-valet.vault.azure.net/keys/valet-receipts
    VALET_KEY_RECEIPTS_PREVIOUS=azure-kv:https://marula-valet.vault.azure.net/keys/valet-receipts/0a1b…

Key ids are derived from the key itself (`receipts-<first 8 of its RFC 7638 thumbprint>`), so a new key gets a new
`kid` with nothing to configure, and a verifier can always find the key that signed a record.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from .crypto import Key, b64u, jwk_thumbprint


class Signer(Protocol):
    kid: str

    @property
    def jwk(self) -> dict[str, str]: ...

    def sign(self, claims: dict[str, Any], headers: dict[str, Any] | None = None) -> str: ...


def kid_for(purpose: str, jwk: dict[str, Any]) -> str:
    return f"{purpose}-{jwk_thumbprint(jwk)[:8]}"


def _jwk_from_public(pub: ec.EllipticCurvePublicKey) -> dict[str, str]:
    if not isinstance(pub.curve, ec.SECP256R1):
        raise ValueError("Valet signs with ES256 only: the key must be EC P-256")
    n = pub.public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}


class RemoteSigner:
    """A key held in a vault or HSM: Valet builds the JWS and asks the vault to sign its SHA-256 digest."""

    provider = "remote"

    def __init__(self, purpose: str, public_jwk: dict[str, str], uri: str):
        self.purpose, self._jwk, self.uri = purpose, public_jwk, uri
        self.kid = kid_for(purpose, public_jwk)

    @property
    def jwk(self) -> dict[str, str]:
        return dict(self._jwk)

    @property
    def thumbprint(self) -> str:
        return jwk_thumbprint(self._jwk)

    def sign(self, claims: dict[str, Any], headers: dict[str, Any] | None = None) -> str:
        head = {"alg": "ES256", "typ": "JWT", "kid": self.kid, **(headers or {})}
        signing_input = (b64u(json.dumps(head, separators=(",", ":")).encode()) + "."
                         + b64u(json.dumps(claims, separators=(",", ":")).encode()))
        h = hashes.Hash(hashes.SHA256())
        h.update(signing_input.encode())
        raw = self._sign_digest(h.finalize())
        if len(raw) != 64:
            raise ValueError("an ES256 signature must be 64 bytes (r || s)")
        return signing_input + "." + b64u(raw)

    def _sign_digest(self, digest: bytes) -> bytes:  # pragma: no cover - implemented by each provider
        raise NotImplementedError


class AzureKeyVaultSigner(RemoteSigner):
    """Azure Key Vault or Managed HSM. Authenticates with the host's managed identity (DefaultAzureCredential).
    The identity needs the `Key Vault Crypto User` role on the key: sign and read the public key, never export."""

    provider = "azure-key-vault"

    def __init__(self, purpose: str, key_id: str, crypto_client=None, public_jwk: dict[str, str] | None = None):
        if crypto_client is None or public_jwk is None:  # pragma: no cover - needs Azure
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.keys import KeyClient
            from azure.keyvault.keys.crypto import CryptographyClient
            cred = DefaultAzureCredential()
            vault, _, rest = key_id.partition("/keys/")
            name, _, version = rest.partition("/")
            key = KeyClient(vault_url=vault, credential=cred).get_key(name, version or None)
            if key.key.crv != "P-256":
                raise ValueError(f"{key_id}: Valet needs an EC P-256 key")
            public_jwk = {"kty": "EC", "crv": "P-256", "x": b64u(key.key.x), "y": b64u(key.key.y)}
            crypto_client = CryptographyClient(key, credential=cred)
            key_id = key.id                                # pin the exact version this instance signs with
        self.client = crypto_client
        super().__init__(purpose, public_jwk, "azure-kv:" + key_id)

    def _sign_digest(self, digest: bytes) -> bytes:
        from_azure = self.client.sign("ES256", digest)      # Key Vault returns r || s for EC keys
        return getattr(from_azure, "signature", from_azure)


class AwsKmsSigner(RemoteSigner):
    """AWS KMS, key spec ECC_NIST_P256 with usage SIGN_VERIFY. Authenticates with the host's IAM role, which needs
    kms:Sign and kms:GetPublicKey on the key, and nothing else."""

    provider = "aws-kms"

    def __init__(self, purpose: str, key_id: str, client=None):
        if client is None:  # pragma: no cover - needs AWS
            import boto3
            client = boto3.client("kms")
        self.client, self.key_id = client, key_id
        der = client.get_public_key(KeyId=key_id)["PublicKey"]
        super().__init__(purpose, _jwk_from_public(serialization.load_der_public_key(der)), "aws-kms:" + key_id)

    def _sign_digest(self, digest: bytes) -> bytes:
        der = self.client.sign(KeyId=self.key_id, Message=digest, MessageType="DIGEST",
                               SigningAlgorithm="ECDSA_SHA_256")["Signature"]
        r, s = decode_dss_signature(der)                   # KMS returns DER; JWS needs r || s
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


class FileSigner:
    """A PEM file. For demos and tests: the private key is in memory and on disk (written with mode 0600)."""

    provider = "file"

    def __init__(self, purpose: str, key: Key, uri: str):
        self.purpose, self.key, self.uri = purpose, key, uri
        self.kid = kid_for(purpose, key.jwk)

    @property
    def jwk(self) -> dict[str, str]:
        return self.key.jwk

    @property
    def thumbprint(self) -> str:
        return self.key.thumbprint

    def sign(self, claims: dict[str, Any], headers: dict[str, Any] | None = None) -> str:
        return self.key.sign(claims, headers={"kid": self.kid, **(headers or {})})


def open_signer(purpose: str, uri: str) -> Signer:
    scheme, _, rest = uri.partition(":")
    if scheme == "file":
        return FileSigner(purpose, Key.load_or_create(Path(rest)), uri)
    if scheme == "azure-kv":
        return AzureKeyVaultSigner(purpose, rest)
    if scheme == "aws-kms":
        return AwsKmsSigner(purpose, rest)
    raise ValueError(f"unknown key provider in {uri!r}: use file:, azure-kv: or aws-kms:")


class KeyRing:
    """One purpose's keys: the active signer, and previous keys kept for verification during rotation."""

    def __init__(self, purpose: str, active: Signer, previous: list[Signer] | None = None):
        self.purpose, self.active, self.previous = purpose, active, list(previous or [])

    @classmethod
    def load(cls, purpose: str, default_file: Path, in_memory: bool = False) -> "KeyRing":
        env = "VALET_KEY_" + purpose.upper().replace("-", "_")
        if in_memory and not os.environ.get(env):
            k = Key.generate()
            return cls(purpose, FileSigner(purpose, k, "memory:"))
        active = open_signer(purpose, os.environ.get(env) or f"file:{default_file}")
        prev = [open_signer(purpose, u.strip()) for u in os.environ.get(env + "_PREVIOUS", "").split(",") if u.strip()]
        return cls(purpose, active, prev)

    @property
    def all(self) -> list[Signer]:
        return [self.active, *self.previous]

    def jwks(self) -> list[dict[str, Any]]:
        return [{**s.jwk, "kid": s.kid, "use": "sig", "alg": "ES256"} for s in self.all]

    def find(self, kid: str | None) -> list[dict[str, Any]]:
        """Public keys to try for a signature: the one named by `kid`, or every key for records signed before
        key ids were recorded."""
        named = [s.jwk for s in self.all if s.kid == kid]
        return named or [s.jwk for s in self.all]

    def custody(self) -> dict[str, Any]:
        return {"provider": getattr(self.active, "provider", "unknown"), "kid": self.active.kid,
                "previous": [s.kid for s in self.previous]}


def jws_kid(token: str) -> str | None:
    try:
        head = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
        return head.get("kid")
    except (ValueError, IndexError):
        return None
