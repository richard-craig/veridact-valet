"""
Key management (valet/common/signers.py; technical design section 21): keys behind one interface whether they are
files, Azure Key Vault keys or AWS KMS keys; rotation without breaking old signatures; and start-up refusing demo
secrets on a real deployment.
"""
from __future__ import annotations

import asyncio
import os
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature

from valet.bank.config import BankConfig
from valet.common.crypto import Key, verify
from valet.common.signers import AwsKmsSigner, AzureKeyVaultSigner, FileSigner, KeyRing, jws_kid, kid_for
from valet.harness import Harness


class FakeKms:
    """Behaves like boto3's KMS client for one ECC_NIST_P256 key: DER public key, DER signatures over a digest."""

    def __init__(self):
        self.private = ec.generate_private_key(ec.SECP256R1())
        self.calls = []

    def get_public_key(self, KeyId):
        return {"PublicKey": self.private.public_key().public_bytes(serialization.Encoding.DER,
                                                                    serialization.PublicFormat.SubjectPublicKeyInfo)}

    def sign(self, KeyId, Message, MessageType, SigningAlgorithm):
        assert MessageType == "DIGEST" and SigningAlgorithm == "ECDSA_SHA_256" and len(Message) == 32
        self.calls.append(KeyId)
        return {"Signature": self.private.sign(Message, ec.ECDSA(Prehashed(hashes.SHA256())))}


class FakeKeyVault:
    """Behaves like Azure's CryptographyClient.sign for an EC P-256 key: r || s over a digest."""

    def __init__(self, key: Key):
        self.key = key

    def sign(self, algorithm, digest):
        assert algorithm == "ES256" and len(digest) == 32
        r, s = decode_dss_signature(self.key.private.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256()))))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def test_aws_kms_signer_produces_standard_es256_jws():
    kms = FakeKms()
    s = AwsKmsSigner("receipts", "alias/valet-receipts", client=kms)
    token = s.sign({"seq": 1, "hash": "h"}, headers={"typ": "valet-receipt+jwt"})
    assert verify(token, s.jwk) == {"seq": 1, "hash": "h"}
    assert jws_kid(token) == s.kid == kid_for("receipts", s.jwk) and kms.calls == ["alias/valet-receipts"]


def test_azure_key_vault_signer_produces_standard_es256_jws():
    k = Key.generate()
    s = AzureKeyVaultSigner("as", "https://v.vault.azure.net/keys/valet-as/1", crypto_client=FakeKeyVault(k),
                            public_jwk=k.jwk)
    token = s.sign({"sub": "x"})
    assert verify(token, k.jwk) == {"sub": "x"} and jws_kid(token).startswith("as-")


def test_key_files_are_private_to_the_service_account(tmp_path: Path):
    p = tmp_path / "keys" / "receipts.pem"
    Key.load_or_create(p)
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(p.parent).st_mode) == 0o700


def _reload_keys(bank) -> None:
    """What a restart does: read the key configuration again. The database stays."""
    bank.as_keys = KeyRing.load("as", bank.cfg.data_dir / "keys" / "authorization-server.pem")
    bank.receipt_keys = KeyRing.load("receipts", bank.cfg.data_dir / "keys" / "receipts.pem")
    bank.as_key, bank.receipt_key = bank.as_keys.active, bank.receipt_keys.active
    bank.receipts.key, bank.receipts.ring = bank.receipt_key, bank.receipt_keys


def test_rotation_keeps_old_receipts_and_tokens_verifiable(tmp_path: Path, monkeypatch):
    async def t():
        old, as_old = tmp_path / "old.pem", tmp_path / "as-old.pem"
        monkeypatch.setenv("VALET_KEY_RECEIPTS", f"file:{old}")
        monkeypatch.setenv("VALET_KEY_AS", f"file:{as_old}")
        h = Harness(data_dir=tmp_path / "bank")
        await h.connect()
        await h.kaya.accounts()
        old_kid = h.bank.receipt_keys.active.kid
        token = h.kaya.session.access_token

        # Rotate both keys: new active keys, the old ones kept as previous for verification.
        monkeypatch.setenv("VALET_KEY_RECEIPTS", f"file:{tmp_path / 'new.pem'}")
        monkeypatch.setenv("VALET_KEY_RECEIPTS_PREVIOUS", f"file:{old}")
        monkeypatch.setenv("VALET_KEY_AS", f"file:{tmp_path / 'as-new.pem'}")
        monkeypatch.setenv("VALET_KEY_AS_PREVIOUS", f"file:{as_old}")
        _reload_keys(h.bank)
        assert h.bank.receipt_keys.active.kid != old_kid
        kids = {k["kid"] for k in h.bank.as_keys.jwks() + h.bank.receipt_keys.jwks()}
        assert old_kid in kids and len(kids) == 4                 # active and previous, both purposes, published
        assert h.bank.verify_access_token(token)["grant_id"]      # a token signed before the rotation still works
        await h.kaya.accounts()                                   # new receipts, signed with the new key
        assert h.bank.receipts.verify_chain()["ok"]               # old and new receipts verify together

        # Retire the old receipt key: receipts it signed no longer verify against the published keys.
        monkeypatch.delenv("VALET_KEY_RECEIPTS_PREVIOUS")
        _reload_keys(h.bank)
        assert not h.bank.receipts.verify_chain()["ok"]
    asyncio.run(t())


def test_https_deployment_refuses_demo_secrets():
    cfg = BankConfig(issuer="https://bank.example", session_secret="demo-only-secret")
    assert cfg.secret_problems()
    with pytest.raises(RuntimeError, match="refusing to start"):
        _start(cfg)
    assert BankConfig(issuer="https://bank.example", session_secret="x" * 40).secret_problems() == []
    assert BankConfig(issuer="http://localhost:8000", session_secret="demo-only-secret").secret_problems() == []
    assert BankConfig(issuer="https://b.example", session_secret="x" * 40, handoff_secret="short").secret_problems()


def _start(cfg):
    from valet.bank.context import Bank
    cfg.db_path = ":memory:"
    Bank(cfg)


def test_readiness_reports_key_custody():
    h = Harness()
    keys = h.bank.readiness()["keys"]
    assert keys["receipts"]["provider"] == "file" and keys["as"]["kid"].startswith("as-")
