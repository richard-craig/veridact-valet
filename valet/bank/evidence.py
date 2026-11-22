"""
Evidence packs: everything the bank holds about one grant or one agent, exported in a form anyone can check offline
(design section 8.3).

A dispute, an incident review or a regulator asks the same thing: show what happened, and show the record was not
changed afterwards. A pack holds:

  - the grants in scope (terms, status, key binding, consent hash, mandate version)
  - every receipt for them: the record, its hash and the bank's signature
  - the payment intents and the bank's answers
  - every policy document those receipts name (policy.py), so the rules in force can be replayed
  - the denylist entries that reach them
  - the head of the whole chain at export time, signed, and the chain check run at export
  - the bank's public receipt key, and a signature by that key over the whole pack

`verify_pack` checks a pack with nothing but the pack and the bank's published receipt key. Pass that key as
`trusted_jwk`: the copy inside the pack is a convenience and proves nothing on its own.

What a pack does not prove (stated so nobody over-claims): receipts sit in one bank-wide chain, so a pack shows each
receipt is signed and unaltered and links any receipts that are consecutive, but not that no receipt for this grant
is missing between them. Per-grant chains (design section 8, deferred) close that.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import jwt

from ..common.signers import jws_kid
from ..common.crypto import digest, verify
from .config import SAST
from .context import Bank
from .policy import Policy

FORMAT = "valet-evidence-pack/1"


class EvidenceNotFound(Exception):
    """Nothing matches the request. `code` is a fixed, safe message for the caller."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code
_GRANT_FIELDS = ("id", "customer", "sub", "client_id", "level", "details", "status", "created", "expires", "jkt",
                 "consent_hash", "version", "issuer")
_INTENT_FIELDS = ("id", "grant_id", "client_id", "idem_key", "request_digest", "detail", "amount", "month", "status",
                  "basis", "approval", "reason", "bank_payment_id", "created", "updated", "escalated", "channel",
                  "mandate_version")


def _ints(row: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    """Times as whole seconds: the canonical hash is exact only for strings, integers and booleans."""
    out = {}
    for f in fields:
        v = row.get(f)
        out[f] = int(v) if isinstance(v, float) else v
    return out


def build(bank: Bank, grant_id: str | None = None, client_id: str | None = None, reason: str = "") -> dict[str, Any]:
    """An evidence pack for one grant, or for every grant of one agent. Raises EvidenceNotFound if nothing matches."""
    store = bank.store
    if grant_id:
        ids = [grant_id] if store.grant(grant_id) else []
        scope = {"grant_id": grant_id}
    elif client_id:
        ids = [r["id"] for r in store.q("SELECT id FROM grants WHERE client_id=? ORDER BY created", client_id)]
        scope = {"client_id": client_id}
    else:
        raise EvidenceNotFound("scope_required")
    if not ids:
        raise EvidenceNotFound("no_matching_grant")
    grants = [_ints(store.grant(i), _GRANT_FIELDS) for i in ids]

    rows = store.q("SELECT * FROM receipts ORDER BY seq")
    wanted, receipts, policy_hashes = set(ids), [], []
    for r in rows:
        rec = json.loads(r["record"])
        if rec.get("grant_id") in wanted or set(rec.get("grants") or []) & wanted:
            receipts.append({"record": rec, "hash": r["hash"], "signature": r["signature"]})
            ph = (rec.get("policy") or {}).get("hash")
            if ph and ph not in policy_hashes:
                policy_hashes.append(ph)
    head = rows[-1] if rows else None

    intents = []
    for i in ids:
        for row in store.q("SELECT * FROM payment_intents WHERE grant_id=? ORDER BY created", i):
            d = dict(row)
            d["detail"] = json.loads(d["detail"])
            intents.append(_ints(d, _INTENT_FIELDS))

    clients = sorted({g["client_id"] for g in grants})
    keys = sorted({g["jkt"] for g in grants if g.get("jkt")})
    operators = sorted({rec.operator for c in clients if (rec := bank.registry.lookup(c))})
    denylist = [{"kind": r["kind"], "value": r["value"], "reason": r["reason"], "added": int(r["added"])}
                for r in store.q("SELECT * FROM denylist")
                if (r["kind"], r["value"]) in {*(("client_id", c) for c in clients), *(("jkt", k) for k in keys),
                                               *(("operator", o) for o in operators)}]

    body: dict[str, Any] = {
        "format": FORMAT,
        "generated_at": datetime.now(SAST).isoformat(timespec="seconds"),
        "bank": {"issuer": bank.cfg.issuer, "receipt_key": bank.receipt_key.jwk,
                 "receipt_keys": bank.receipt_keys.jwks()},
        "scope": scope,
        "reason": reason[:200],
        "grants": grants,
        "receipts": receipts,
        "payment_intents": intents,
        "policies": [p for h in policy_hashes if (p := bank.policy.get(h))],
        "denylist": denylist,
        "chain": {"check_at_export": bank.receipts.verify_chain(),
                  "head": {"seq": head["seq"], "hash": head["hash"], "signature": head["signature"]} if head else None},
    }
    body["pack_signature"] = bank.receipt_key.sign({"pack": digest(body)}, headers={"typ": "valet-evidence+jwt"})
    return body


def verify_pack(pack: dict[str, Any], trusted_jwk: dict[str, Any] | None = None) -> dict[str, Any]:
    """Check a pack offline. `trusted_jwk` is the bank's published receipt key; without it, the pack's own copy is
    used and the result says so."""
    problems: list[str] = []
    bank = pack.get("bank", {})
    if isinstance(trusted_jwk, list):
        keys = trusted_jwk                                 # the bank's published receipt keys (JWKS entries)
    elif trusted_jwk:
        keys = [trusted_jwk]
    else:
        keys = bank.get("receipt_keys") or ([bank["receipt_key"]] if bank.get("receipt_key") else [])
    if not keys:
        return {"ok": False, "problems": ["no receipt key to check against"], "receipts_checked": 0}
    body = {k: v for k, v in pack.items() if k != "pack_signature"}

    def signed(token: str, expect: dict[str, Any], what: str) -> None:
        kid = jws_kid(token)
        named = [k for k in keys if k.get("kid") and k.get("kid") == kid] or keys
        last: Exception | None = None
        for k in named:
            try:
                if verify(token, {f: k[f] for f in ("kty", "crv", "x", "y")}) != expect:
                    problems.append(f"{what}: the signature covers different content")
                return
            except jwt.PyJWTError as e:
                last = e
        problems.append(f"{what}: bad signature ({last})")

    signed(pack.get("pack_signature", ""), {"pack": digest(body)}, "pack")
    prev: dict[str, Any] | None = None
    for item in pack.get("receipts", []):
        rec, seq = item["record"], item["record"].get("seq")
        if digest(rec) != item["hash"]:
            problems.append(f"receipt {seq}: record was altered")
        signed(item["signature"], {"seq": seq, "hash": item["hash"]}, f"receipt {seq}")
        if prev is not None:
            if seq <= prev["record"]["seq"]:
                problems.append(f"receipt {seq}: out of order")
            elif seq == prev["record"]["seq"] + 1 and rec.get("prev") != prev["hash"]:
                problems.append(f"receipt {seq}: does not link to receipt {prev['record']['seq']}")
        prev = item
    known = {p["hash"] for p in pack.get("policies", [])}
    for p in pack.get("policies", []):
        if not Policy.verify(p):
            problems.append(f"policy {p.get('version')}: document does not match its hash")
    for item in pack.get("receipts", []):
        ph = (item["record"].get("policy") or {}).get("hash")
        if ph and ph not in known:
            problems.append(f"receipt {item['record']['seq']}: names a policy the pack does not include")
    head = (pack.get("chain") or {}).get("head")
    if head:
        signed(head["signature"], {"seq": head["seq"], "hash": head["hash"]}, "chain head")
    return {"ok": not problems, "problems": problems, "receipts_checked": len(pack.get("receipts", [])),
            "key": "trusted" if trusted_jwk else "pack's own copy (pin the bank's published key)"}
