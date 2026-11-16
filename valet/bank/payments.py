"""
Payment intents: one durable record per payment an agent asks for (design section 5.1).

Valet never executes a payment. It records the intent, holds the amount against the mandate, hands the bank's core
banking API one idempotent instruction (core.py), and records what the bank said. The intent is what makes that safe
across retries, crashes and timeouts:

    approval_required --(customer approves; single-use token)--> reserved
    reserved --> executing --> confirmed          the bank paid; the month's spend is updated
                           --> failed             the bank declined; the hold is released
                           --> unknown_outcome    the bank did not answer; the hold stays until reconciled

Rules:
  - One intent per grant and Idempotency-Key (two customers of one agent may use the same key). The same key with the same payment continues or replays that intent and
    can never pay twice; the same key with a different payment is refused.
  - The limit check and the hold happen in one locked step, so two parallel payments cannot both pass a limit only
    one fits under. Held amounts (reserved, executing, unknown_outcome) count against the month.
  - The intent id is the idempotency key Valet gives the bank, so a retry after a crash or a timeout re-sends the
    same instruction and the bank answers with the original result.
  - A timeout is not a failure. The hold is kept until the bank says paid or declined.
  - A customer approval is spent when its intent is reserved. A decline by the bank ends the intent and the approval.
"""
from __future__ import annotations

import json
import time
from typing import Any

from ..common.crypto import random_id
from ..common.money import CURRENCY, to_str
from .core import CoreBanking, CoreResult, CoreUnavailable, PaymentInstruction
from .receipts import Receipts
from .store import Store, month_key

SCHEMA = """
CREATE TABLE IF NOT EXISTS payment_intents (id TEXT PRIMARY KEY, grant_id TEXT, client_id TEXT, idem_key TEXT,
    request_digest TEXT, detail TEXT, amount INTEGER, month TEXT, status TEXT, basis TEXT, approval TEXT, reason TEXT,
    bank_payment_id TEXT, outcome TEXT, created REAL, updated REAL, expires REAL, channel TEXT DEFAULT 'api');
DROP INDEX IF EXISTS payment_intents_idem;
CREATE UNIQUE INDEX IF NOT EXISTS payment_intents_grant_key ON payment_intents (grant_id, idem_key);
CREATE INDEX IF NOT EXISTS payment_intents_held ON payment_intents (grant_id, month, status);
"""

HELD = ("reserved", "executing", "unknown_outcome")      # money is held against the mandate
_HELD_SQL = "('reserved','executing','unknown_outcome')"

# What the receipt says about the customer's intent for this payment (design section 8.1).
EVIDENCE = {"grant": "standing_mandate", "approval": "customer_confirmed"}


class Payments:
    def __init__(self, store: Store, core: CoreBanking, receipts: Receipts, reconcile_after: int = 30,
                 abandon_after: int = 900):
        self.store, self.core, self.receipts = store, core, receipts
        self.reconcile_after, self.abandon_after = reconcile_after, abandon_after
        store.db.executescript(SCHEMA)
        if "channel" not in {c["name"] for c in store.db.execute("PRAGMA table_info(payment_intents)")}:
            store.db.execute("ALTER TABLE payment_intents ADD COLUMN channel TEXT DEFAULT 'api'")   # a 0.4 database

    # ------------------------------------------------------------- reads
    def get(self, intent_id: str) -> dict[str, Any] | None:
        row = self.store.one("SELECT * FROM payment_intents WHERE id=?", intent_id)
        return self._view(row)

    def by_key(self, grant_id: str, key: str) -> dict[str, Any] | None:
        return self._view(self.store.one("SELECT * FROM payment_intents WHERE grant_id=? AND idem_key=?", grant_id, key))

    def by_approval(self, grant_id: str, approval_id: str) -> dict[str, Any] | None:
        return self._view(self.store.one("SELECT * FROM payment_intents WHERE grant_id=? AND approval=?", grant_id, approval_id))

    @staticmethod
    def _view(row: Any) -> dict[str, Any] | None:
        if not row:
            return None
        i = dict(row)
        i["detail"] = json.loads(i["detail"])
        i["outcome"] = json.loads(i["outcome"]) if i["outcome"] else None
        return i

    def reserved(self, grant_id: str, month: str | None = None) -> int:
        """Money held for payments the bank has not yet confirmed or declined."""
        row = self.store.one(f"SELECT COALESCE(SUM(amount),0) n FROM payment_intents WHERE grant_id=? AND month=? "
                             f"AND status IN {_HELD_SQL}", grant_id, month or month_key())
        return row["n"]

    # ------------------------------------------------------------- writes (call inside store.tx())
    def create(self, grant: dict[str, Any], key: str, request_digest: str, detail: dict[str, Any], cents: int,
               status: str, basis: str, reason: str | None = None, expires: float | None = None,
               approval: str | None = None, channel: str = "api") -> dict[str, Any]:
        iid, now = random_id("pi", 12), time.time()
        self.store.x("INSERT INTO payment_intents (id, grant_id, client_id, idem_key, request_digest, detail, amount, "
                     "month, status, basis, approval, reason, created, updated, expires, channel) "
                     "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", iid, grant["id"], grant["client_id"], key, request_digest,
                     json.dumps(detail), cents, month_key(), status, basis, approval, reason, now, now, expires, channel)
        return self.get(iid)

    def link_approval(self, grant_id: str, request_digest: str, approval_id: str) -> str | None:
        """Bind a new approval request to the held intent it is for. Returns the intent id."""
        row = self.store.one("SELECT id FROM payment_intents WHERE grant_id=? AND request_digest=? AND "
                             "status='approval_required' AND approval IS NULL ORDER BY created DESC LIMIT 1",
                             grant_id, request_digest)
        if row:
            self.store.x("UPDATE payment_intents SET approval=?, updated=? WHERE id=?", approval_id, time.time(), row["id"])
        return row["id"] if row else None

    def reserve_approved(self, intent: dict[str, Any], approval_ref: str) -> bool:
        """approval_required -> reserved, once. The caller has checked the approval; this is the single-use gate."""
        return self.store.x("UPDATE payment_intents SET status='reserved', basis='approval', approval=?, month=?, updated=? "
                            "WHERE id=? AND status='approval_required'", approval_ref, month_key(), time.time(),
                            intent["id"]) == 1

    # ------------------------------------------------------------- execution
    def execute(self, intent: dict[str, Any], grant: dict[str, Any]) -> dict[str, Any]:
        """Hand a held intent to the bank and record the answer. Safe to call again for the same intent."""
        store, now = self.store, time.time()
        if store.x(f"UPDATE payment_intents SET status='executing', updated=? WHERE id=? AND status IN {_HELD_SQL}",
                   now, intent["id"]) != 1:
            return self.get(intent["id"])                       # already settled
        d = intent["detail"]
        try:
            result = self.core.execute(PaymentInstruction(
                payment_intent_id=intent["id"], customer=grant["customer"], from_account=d["from"],
                to_name=d["to"]["name"], to_account=d["to"]["account"], cents=intent["amount"],
                reference=d.get("reference", ""), by_agent=grant["client_id"]))
        except CoreUnavailable as e:
            if store.x("UPDATE payment_intents SET status='unknown_outcome', reason=?, updated=? WHERE id=? AND "
                       "status='executing'", str(e)[:200] or "no answer from the bank's payment system", time.time(),
                       intent["id"]) == 1 and intent["status"] != "unknown_outcome":
                self._receipt(intent, grant, "unknown", reason="the bank's payment system did not answer; held until reconciled")
            return self.get(intent["id"])
        return self.settle(intent, grant, result)

    def settle(self, intent: dict[str, Any], grant: dict[str, Any], result: CoreResult) -> dict[str, Any]:
        store, paid = self.store, result.status == "paid"
        with store.tx():
            changed = store.db.execute(
                f"UPDATE payment_intents SET status=?, bank_payment_id=?, reason=?, updated=? WHERE id=? AND status IN {_HELD_SQL}",
                ("confirmed" if paid else "failed", result.bank_payment_id, result.reason, time.time(),
                 intent["id"])).rowcount == 1
            if changed and paid:
                store.db.execute("INSERT INTO ledger VALUES (?,?,?) ON CONFLICT(grant_id,month) DO UPDATE SET "
                                 "spent=spent+excluded.spent", (grant["id"], intent["month"], intent["amount"]))
        if changed:
            fresh = self.get(intent["id"])
            rec = (self._receipt(fresh, grant, "allowed", bank_payment_id=result.bank_payment_id) if paid else
                   self._receipt(fresh, grant, "failed", reason=result.reason or "declined by the bank"))
            store.x("UPDATE payment_intents SET outcome=? WHERE id=?", json.dumps(self._outcome(fresh, grant, rec["hash"])),
                    intent["id"])
        return self.get(intent["id"])

    def reconcile(self) -> list[dict[str, Any]]:
        """Ask the bank about every intent left held, e.g. after a timeout or a crash. Run on a schedule.

        Paid or declined at the bank: settle it. Unknown to the bank: leave it held until `abandon_after`, then release
        the hold. A bank's adapter must then refuse that intent id if it ever arrives late (core.py).
        """
        now, out = time.time(), []
        for row in self.store.q(f"SELECT id FROM payment_intents WHERE status IN {_HELD_SQL} AND updated<?",
                                now - self.reconcile_after):
            intent = self.get(row["id"])
            grant = self.store.grant(intent["grant_id"])
            try:
                result = self.core.status(intent["id"])
            except CoreUnavailable:
                continue
            if result is None and now - intent["updated"] < self.abandon_after:
                continue
            was = intent["status"]
            done = self.settle(intent, grant, result or CoreResult("declined", None, "not_received_by_the_bank"))
            out.append({"payment_intent_id": done["id"], "was": was, "now": done["status"]})
        return out

    # ------------------------------------------------------------- what the agent is told
    def response(self, intent: dict[str, Any], grant: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        """The answer for an intent in its current state: the same for the first call and for every retry."""
        if intent["outcome"]:
            return intent["outcome"]["http"], intent["outcome"]["body"]
        if intent["status"] in ("confirmed", "failed"):          # settled, but the crash came before the answer was stored
            o = self._outcome(intent, grant, None)
            return o["http"], o["body"]
        return 202, {"status": "pending", "payment_intent_id": intent["id"], "state": intent["status"],
                     "detail": "The bank has not confirmed this payment yet. It may have been paid. Retry with the same "
                               "Idempotency-Key, or read /api/payments/" + intent["id"] + "; never send it under a new key."}

    def _outcome(self, intent: dict[str, Any], grant: dict[str, Any], receipt_hash: str | None) -> dict[str, Any]:
        from . import levels as L
        d = intent["detail"]
        if intent["status"] == "confirmed":
            body: dict[str, Any] = {"status": "paid", "payment_intent_id": intent["id"],
                                    "bank_payment_id": intent["bank_payment_id"], "to": d["to"]["name"],
                                    "amount": to_str(intent["amount"]), "currency": CURRENCY}
            if receipt_hash:
                body["receipt"] = receipt_hash
            limit = L.monthly_limit(grant["details"])
            if limit is not None:
                body |= {"spent_this_month": to_str(self.store.spent(grant["id"], intent["month"])),
                         "monthly_limit": to_str(limit)}
            return {"http": 200, "body": body}
        funds = intent["reason"] == "insufficient_funds"
        return {"http": 422, "body": {
            "error": "insufficient_funds" if funds else "payment_declined",
            "error_description": "not enough money in the account" if funds else
                                 f"the bank declined this payment ({intent['reason']})",
            "payment_intent_id": intent["id"]}}

    def _receipt(self, intent: dict[str, Any], grant: dict[str, Any], outcome: str, **kw: Any) -> dict[str, Any]:
        d = intent["detail"]
        fields: dict[str, Any] = {
            "detail": {"to": d["to"]["name"], "account": d["to"]["account"], "amount": d["amount"]["amount"],
                       "currency": d["amount"]["currency"], "reference": d.get("reference", "")},
            "payment_intent": intent["id"], "idempotency_key": intent["idem_key"], "channel": intent.get("channel") or "api",
            "intent_evidence": EVIDENCE.get(intent["basis"], "standing_mandate")}
        if intent["basis"] == "approval":
            fields["approval"] = intent["approval"]
        return self.receipts.append(grant_id=grant["id"], agent=grant["client_id"], customer=grant["customer"],
                                    action="payment", outcome=outcome,
                                    basis=intent["basis"] if outcome == "allowed" else ("refused" if outcome == "failed" else intent["basis"]),
                                    grant_level=grant["level"], **fields, **kw)
