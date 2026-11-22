"""
Receipts: a signed, hash-chained record of every agent decision, kept at the bank.

hash      = sha256 over the canonical record (which includes the previous hash)
signature = ES256 JWS by the bank's receipt key over {"seq", "hash"}
Changing or deleting any receipt breaks every later link.

Personal data outside the chain (POPIA). Free text that can identify a person, such as the agent's triggering
instruction and the mandate's purpose, is never written into the chained record. The record holds a salted hash
(`personal: {field: "sha256:..."}`); the value and its salt sit in `receipt_personal`, which the bank can erase
(`erase_personal`) without breaking the chain. Anyone given the value and salt can check it against the receipt.
Payee names and account numbers in `detail` are still in the record: moving them out is the next step (design §8).
"""
from __future__ import annotations

import json
import secrets
from datetime import datetime
from typing import Any

import jwt

from ..common.crypto import Key, digest, verify
from ..common.poppy import current_session
from ..common.signers import jws_kid
from .config import SAST
from .store import Store

GENESIS = "sha256:" + "0" * 64
PERSONAL_FIELDS = ("agent_supplied_instruction", "intent")

SCHEMA = """
CREATE TABLE IF NOT EXISTS receipt_personal (seq INTEGER, field TEXT, value TEXT, salt TEXT, grant_id TEXT,
    PRIMARY KEY (seq, field));
"""


def personal_hash(value: str, salt: str) -> str:
    return digest({"salt": salt, "value": value})


class Receipts:
    def __init__(self, store: Store, key: Key, ring: Any = None):
        self.store = store
        self.key = key                   # the active receipt signer (a Key, or a signer from valet/common/signers.py)
        self.ring = ring                 # all receipt keys, including previous ones kept for verification
        self.policy: Any = None          # set by the bank once its policy is known (policy.py)
        store.db.executescript(SCHEMA)

    def append(self, **fields: Any) -> dict[str, Any]:
        if fields.get("grant_id") and "mandate" not in fields:
            g = self.store.one("SELECT version, details FROM grants WHERE id=?", fields["grant_id"])
            fields["mandate"] = {"id": fields["grant_id"], "version": (g["version"] if g else None) or 1}
            purpose = next((d.get("intent") for d in json.loads(g["details"]) if d.get("intent")), None) if g else None
            if purpose and "intent" not in fields:
                fields["intent"] = purpose
        if "session" not in fields and (session := current_session.get()):
            fields["session"] = session            # the agent's Poppy Session: evidence of continuity, never access
        if self.policy is not None and "policy" not in fields:
            fields["policy"] = self.policy.ref       # the bank's rules in force, besides the customer's mandate
        personal = {k: str(fields.pop(k)) for k in PERSONAL_FIELDS if fields.get(k)}
        for k in (*PERSONAL_FIELDS, "reason_code"):
            if k in fields and fields[k] is None:
                del fields[k]
        with self.store.lock:
            last = self.store.one("SELECT seq, hash FROM receipts ORDER BY seq DESC LIMIT 1")
            seq = (last["seq"] + 1) if last else 1
            salts = {k: secrets.token_urlsafe(16) for k in personal}
            record = {"seq": seq, "prev": last["hash"] if last else GENESIS,
                      "time": datetime.now(SAST).isoformat(timespec="seconds"), **fields}
            if personal:
                record["personal"] = {k: personal_hash(v, salts[k]) for k, v in personal.items()}
            h = digest(record)
            sig = self.key.sign({"seq": seq, "hash": h}, headers={"typ": "valet-receipt+jwt"})
            self.store.x("INSERT INTO receipts VALUES (?,?,?,?)", seq, json.dumps(record), h, sig)
            for k, v in personal.items():
                self.store.x("INSERT INTO receipt_personal VALUES (?,?,?,?,?)", seq, k, v, salts[k], fields.get("grant_id"))
        return {**record, **personal, "hash": h}

    def _reveal(self, rec: dict[str, Any]) -> dict[str, Any]:
        """The record with its personal values joined back in, for the bank's own screens. Erased values stay hashes."""
        if not rec.get("personal"):
            return rec
        rows = self.store.q("SELECT field, value FROM receipt_personal WHERE seq=?", rec["seq"])
        return {**rec, **{r["field"]: r["value"] for r in rows}}

    def personal(self, seq: int) -> dict[str, dict[str, str]]:
        """A receipt's personal values with their salts, so a dispute can check them against the chained hashes."""
        return {r["field"]: {"value": r["value"], "salt": r["salt"]}
                for r in self.store.q("SELECT field, value, salt FROM receipt_personal WHERE seq=?", seq)}

    def erase_personal(self, grant_id: str) -> int:
        """Erase a grant's personal values (POPIA). The chain still verifies; the hashes remain."""
        return self.store.x("DELETE FROM receipt_personal WHERE grant_id=?", grant_id)

    def for_grant(self, grant_id: str) -> list[dict[str, Any]]:
        rows = self.store.q("SELECT record, hash FROM receipts ORDER BY seq DESC")
        out = []
        for r in rows:
            rec = json.loads(r["record"])
            if rec.get("grant_id") == grant_id:
                out.append({**self._reveal(rec), "hash": r["hash"]})
        return out

    def verify_chain(self) -> dict[str, Any]:
        prev = GENESIS
        rows = self.store.q("SELECT * FROM receipts ORDER BY seq")
        for r in rows:
            rec = json.loads(r["record"])
            if rec["prev"] != prev:
                return {"ok": False, "broken_at": rec["seq"], "why": "previous hash does not match"}
            if digest(rec) != r["hash"]:
                return {"ok": False, "broken_at": rec["seq"], "why": "record was altered"}
            claims = None
            for jwk in (self.ring.find(jws_kid(r["signature"])) if self.ring else [self.key.jwk]):
                try:
                    claims = verify(r["signature"], jwk)
                    break
                except jwt.PyJWTError:
                    continue
            if claims is None:
                return {"ok": False, "broken_at": rec["seq"], "why": "bad signature"}
            if claims != {"seq": rec["seq"], "hash": r["hash"]}:
                return {"ok": False, "broken_at": rec["seq"], "why": "signature covers a different record"}
            prev = r["hash"]
        return {"ok": True, "count": len(rows), "head": prev}
