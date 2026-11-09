"""
Receipts: a signed, hash-chained record of every agent decision, kept at the bank.

hash      = sha256 over the canonical record (which includes the previous hash)
signature = ES256 JWS by the bank's receipt key over {"seq", "hash"}
Changing or deleting any receipt breaks every later link.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import jwt

from ..common.crypto import Key, digest, verify
from .config import SAST
from .store import Store

GENESIS = "sha256:" + "0" * 64


class Receipts:
    def __init__(self, store: Store, key: Key):
        self.store = store
        self.key = key

    def append(self, **fields: Any) -> dict[str, Any]:
        with self.store.lock:
            last = self.store.one("SELECT seq, hash FROM receipts ORDER BY seq DESC LIMIT 1")
            seq = (last["seq"] + 1) if last else 1
            record = {"seq": seq, "prev": last["hash"] if last else GENESIS,
                      "time": datetime.now(SAST).isoformat(timespec="seconds"), **fields}
            h = digest(record)
            sig = self.key.sign({"seq": seq, "hash": h}, headers={"typ": "valet-receipt+jwt"})
            self.store.x("INSERT INTO receipts VALUES (?,?,?,?)", seq, json.dumps(record), h, sig)
        return {**record, "hash": h}

    def for_grant(self, grant_id: str) -> list[dict[str, Any]]:
        rows = self.store.q("SELECT record, hash FROM receipts ORDER BY seq DESC")
        out = []
        for r in rows:
            rec = json.loads(r["record"])
            if rec.get("grant_id") == grant_id:
                out.append({**rec, "hash": r["hash"]})
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
            try:
                claims = verify(r["signature"], self.key.jwk)
            except jwt.PyJWTError:
                return {"ok": False, "broken_at": rec["seq"], "why": "bad signature"}
            if claims != {"seq": rec["seq"], "hash": r["hash"]}:
                return {"ok": False, "broken_at": rec["seq"], "why": "signature covers a different record"}
            prev = r["hash"]
        return {"ok": True, "count": len(rows), "head": prev}
