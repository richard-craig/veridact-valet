"""
Payment intents: one durable record per payment an agent asks for (design section 5.1).

Valet never executes a payment. It records the intent, holds the amount against the mandate, hands the bank's core
banking API one idempotent instruction (core.py), and records what the bank said. The intent is what makes that safe
across retries, crashes and timeouts:

    approval_required --(customer approves; single-use token)--> reserved
    reserved --> executing --> confirmed          the bank accepted it; the month's spend is updated
                           --> failed             the bank declined; the hold is released
                           --> unknown_outcome    the bank did not answer; the hold stays until reconciled
    any state not yet accepted --(pause, revoke, denylist)--> cancelling --> cancelled   (the bank tombstoned it)
                                                                         --> confirmed   (the bank had accepted it)

The point of no return is the bank's acceptance. Before it, a payment can be cancelled; after it, it completes.
A payment that was never sent (approval_required, reserved) is cancelled at once. One that may have reached the bank
(executing, unknown_outcome) is cancelled only by the bank's cancel-or-confirm answer (core.py): the hold is released
ONLY when the bank says it has tombstoned the instruction, never on a timer.

Rules:
  - One intent per grant and Idempotency-Key (two customers of one agent may use the same key). The same key with the same payment continues or replays that intent and
    can never pay twice; the same key with a different payment is refused.
  - The limit check and the hold happen in one locked step, so two parallel payments cannot both pass a limit only
    one fits under. Held amounts (reserved, executing, unknown_outcome) count against the month.
  - The intent id is the idempotency key Valet gives the bank, so a retry after a crash or a timeout re-sends the
    same instruction and the bank answers with the original result.
  - A timeout is not a failure. The hold is kept until the bank says paid or declined, or tombstones it.
  - After `escalate_after` with no answer, Valet asks the bank to cancel. If the bank cannot say (or the adapter cannot
    tombstone), the payment goes to the operations queue (`escalated()`), still held. Nothing is released on a timer.
  - A customer approval is spent when its intent is reserved. A decline by the bank ends the intent and the approval.
"""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from ..common.crypto import random_id
from ..common.money import CURRENCY, to_str
from .core import CoreBanking, CoreResult, CoreUnavailable, PaymentInstruction
from .receipts import Receipts
from .store import Store, month_key

SCHEMA = """
CREATE TABLE IF NOT EXISTS payment_intents (id TEXT PRIMARY KEY, grant_id TEXT, client_id TEXT, idem_key TEXT,
    request_digest TEXT, detail TEXT, amount INTEGER, month TEXT, status TEXT, basis TEXT, approval TEXT, reason TEXT,
    bank_payment_id TEXT, outcome TEXT, created REAL, updated REAL, expires REAL, channel TEXT DEFAULT 'api',
    mandate_version INTEGER DEFAULT 1, escalated REAL, reason_code TEXT, instruction TEXT);
DROP INDEX IF EXISTS payment_intents_idem;
CREATE UNIQUE INDEX IF NOT EXISTS payment_intents_grant_key ON payment_intents (grant_id, idem_key);
CREATE INDEX IF NOT EXISTS payment_intents_held ON payment_intents (grant_id, month, status);
"""

HELD = ("reserved", "executing", "unknown_outcome", "cancelling")      # counted against the mandate's limit
_HELD_SQL = "('reserved','executing','unknown_outcome','cancelling')"
_SENDABLE_SQL = "('reserved','executing','unknown_outcome')"          # may be (re)sent to the bank
FINAL = ("confirmed", "failed", "cancelled")

# What the receipt says about the customer's intent for this payment (design section 8.1).
EVIDENCE = {"grant": "standing_mandate", "approval": "customer_confirmed"}


class Payments:
    def __init__(self, store: Store, core: CoreBanking, receipts: Receipts, reconcile_after: int = 30,
                 escalate_after: int = 900):
        self.store, self.core, self.receipts = store, core, receipts
        self.reconcile_after, self.escalate_after = reconcile_after, escalate_after
        # Set by the bank: returns why this grant's agent may not act (the denylist), checked again at execution.
        self.blocked: Callable[[dict[str, Any]], str | None] = lambda grant: None
        store.db.executescript(SCHEMA)
        cols = {c["name"] for c in store.db.execute("PRAGMA table_info(payment_intents)")}
        for col, ddl in (("channel", "TEXT DEFAULT 'api'"), ("mandate_version", "INTEGER DEFAULT 1"),
                         ("escalated", "REAL"), ("reason_code", "TEXT"), ("instruction", "TEXT")):                 # databases from earlier versions
            if col not in cols:
                store.db.execute(f"ALTER TABLE payment_intents ADD COLUMN {col} {ddl}")

    # ------------------------------------------------------------- reads
    def get(self, intent_id: str) -> dict[str, Any] | None:
        row = self.store.one("SELECT * FROM payment_intents WHERE id=?", intent_id)
        return self._view(row)

    def by_key(self, grant_id: str, key: str) -> dict[str, Any] | None:
        return self._view(self.store.one("SELECT * FROM payment_intents WHERE grant_id=? AND idem_key=?", grant_id, key))

    def for_grant(self, grant_id: str) -> list[dict[str, Any]]:
        return [self._view(r) for r in self.store.q("SELECT * FROM payment_intents WHERE grant_id=? ORDER BY created", grant_id)]

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
               approval: str | None = None, channel: str = "api", reason_code: str | None = None,
               instruction: str | None = None) -> dict[str, Any]:
        """`reason_code` is the profile reason a payment was held for approval (mandate.REASONS); `instruction` is
        the agent's own account of what it was asked to do, kept as agent-supplied and outside the receipt chain."""
        iid, now = random_id("pi", 12), time.time()
        self.store.x("INSERT INTO payment_intents (id, grant_id, client_id, idem_key, request_digest, detail, amount, "
                     "month, status, basis, approval, reason, created, updated, expires, channel, mandate_version, "
                     "reason_code, instruction) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", iid, grant["id"],
                     grant["client_id"], key, request_digest, json.dumps(detail), cents, month_key(), status, basis,
                     approval, reason, now, now, expires, channel, grant.get("version") or 1, reason_code,
                     instruction or None)
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
        why = self.blocked(grant)
        if why:                                                  # denylisted since the request was checked
            return self.cancel(self.get(intent["id"]), grant, why)
        if store.x(f"UPDATE payment_intents SET status='executing', updated=? WHERE id=? AND status IN {_SENDABLE_SQL}",
                   now, intent["id"]) != 1:
            return self.get(intent["id"])                       # settled, or being cancelled
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
        state = "confirmed" if paid else ("cancelled" if result.reason == "cancelled" else "failed")
        with store.tx():
            changed = store.db.execute(
                f"UPDATE payment_intents SET status=?, bank_payment_id=?, reason=?, updated=? WHERE id=? AND status IN {_HELD_SQL}",
                (state, result.bank_payment_id, result.reason if not paid else None, time.time(),
                 intent["id"])).rowcount == 1
            if changed and paid:
                store.db.execute("INSERT INTO ledger VALUES (?,?,?) ON CONFLICT(grant_id,month) DO UPDATE SET "
                                 "spent=spent+excluded.spent", (grant["id"], intent["month"], intent["amount"]))
        if changed:
            fresh = self.get(intent["id"])
            rec = (self._receipt(fresh, grant, "allowed", bank_payment_id=result.bank_payment_id) if paid else
                   self._receipt(fresh, grant, "cancelled", reason="cancelled before the bank accepted it")
                   if state == "cancelled" else
                   self._receipt(fresh, grant, "failed", reason=result.reason or "declined by the bank"))
            store.x("UPDATE payment_intents SET outcome=? WHERE id=?", json.dumps(self._outcome(fresh, grant, rec["hash"])),
                    intent["id"])
        return self.get(intent["id"])

    def cancel(self, intent: dict[str, Any], grant: dict[str, Any], why: str) -> dict[str, Any]:
        """Cancel a payment the bank has not accepted. Never sent: cancelled at once. Possibly sent: ask the bank to
        cancel-or-confirm, and release the hold only if it tombstones the instruction. Safe to call again."""
        store, iid = self.store, intent["id"]
        if intent["status"] in FINAL:
            return intent
        if intent["status"] in ("approval_required", "reserved"):              # never reached the bank
            if store.x("UPDATE payment_intents SET status='cancelled', reason=?, updated=? WHERE id=? AND status=?",
                       why, time.time(), iid, intent["status"]) == 1:
                return self._cancelled(iid, grant, why)
            intent = self.get(iid)                                              # moved on meanwhile: go round again
            return self.cancel(intent, grant, why) if intent["status"] not in ("approval_required", "reserved") else intent
        store.x(f"UPDATE payment_intents SET status='cancelling', reason=?, updated=? WHERE id=? AND status IN {_HELD_SQL}",
                why, time.time(), iid)
        return self._ask_bank_to_cancel(self.get(iid), grant)

    def _ask_bank_to_cancel(self, intent: dict[str, Any], grant: dict[str, Any]) -> dict[str, Any]:
        if intent["status"] in FINAL:
            return intent
        try:
            if not self.core.supports_cancel:
                raise CoreUnavailable("this payments adapter cannot cancel")
            answer = self.core.cancel(intent["id"])
        except CoreUnavailable:
            return intent                                       # still held; reconciliation asks again
        if answer.status == "already_accepted":
            return self.settle(intent, grant, CoreResult("paid", answer.bank_payment_id))
        return self.settle(intent, grant, CoreResult("declined", None, "cancelled"))   # tombstoned: release

    def _cancelled(self, iid: str, grant: dict[str, Any], why: str) -> dict[str, Any]:
        fresh = self.get(iid)
        rec = self._receipt(fresh, grant, "cancelled", reason=why)
        self.store.x("UPDATE payment_intents SET outcome=? WHERE id=?",
                     json.dumps(self._outcome(fresh, grant, rec["hash"])), iid)
        return self.get(iid)

    def stop_grant(self, grant: dict[str, Any], why: str) -> dict[str, int]:
        """The customer paused or revoked, or the bank stopped the agent: cancel every payment not yet accepted.
        Returns what happened, so the customer can be told if one was already with the bank."""
        counts = {"cancelled": 0, "already_paid": 0, "with_bank": 0}
        for row in self.store.q(f"SELECT id FROM payment_intents WHERE grant_id=? AND status IN "
                                f"('approval_required','reserved','executing','unknown_outcome','cancelling')", grant["id"]):
            done = self.cancel(self.get(row["id"]), grant, why)
            key = {"cancelled": "cancelled", "confirmed": "already_paid"}.get(done["status"], "with_bank")
            counts[key] += 1
        return counts

    def reconcile(self) -> list[dict[str, Any]]:
        """Ask the bank about every payment still held, e.g. after a timeout, a crash or a cancellation it did not
        answer. Run on a schedule.

        Paid or declined at the bank: settle it. Being cancelled: ask again. Unknown to the bank after
        `escalate_after`: ask it to cancel-or-confirm, and release only on a tombstone. No answer, or an adapter that
        cannot tombstone: escalate to the operations queue, still held. Nothing is released on a timer.
        """
        now, out = time.time(), []
        for row in self.store.q(f"SELECT id FROM payment_intents WHERE status IN {_HELD_SQL} AND updated<?",
                                now - self.reconcile_after):
            intent = self.get(row["id"])
            grant, was = self.store.grant(intent["grant_id"]), intent["status"]
            overdue = now - intent["updated"] >= self.escalate_after
            try:
                result = self.core.status(intent["id"])
            except CoreUnavailable:
                result = None
                if not overdue:
                    continue
            if result is not None:
                done = self.settle(intent, grant, result)
            elif was == "cancelling" or overdue:
                done = self._ask_bank_to_cancel(intent, grant)
            else:
                continue
            if done["status"] in HELD and overdue and not done["escalated"]:
                self.store.x("UPDATE payment_intents SET escalated=? WHERE id=?", now, done["id"])
                self._receipt(done, grant, "escalated", reason="no answer from the bank's payment system; sent to "
                                                               "operations, still held against the limit")
                done = self.get(done["id"])
            out.append({"payment_intent_id": done["id"], "was": was,
                        "now": "escalated" if done["status"] in HELD and done["escalated"] else done["status"]})
        return out

    def escalated(self) -> list[dict[str, Any]]:
        """The operations queue `payments-unknown-outcome`: held payments the bank has not settled or tombstoned."""
        now = time.time()
        return [{"payment_intent_id": r["id"], "grant_id": r["grant_id"], "state": r["status"], "amount": to_str(r["amount"]),
                 "escalated_seconds_ago": int(now - r["escalated"]), "waiting_seconds": int(now - r["created"])}
                for r in self.store.q(f"SELECT * FROM payment_intents WHERE escalated IS NOT NULL AND status IN {_HELD_SQL} "
                                      "ORDER BY escalated")]

    # ------------------------------------------------------------- what the agent is told
    def response(self, intent: dict[str, Any], grant: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        """The answer for an intent in its current state: the same for the first call and for every retry."""
        if intent["outcome"]:
            return intent["outcome"]["http"], intent["outcome"]["body"]
        if intent["status"] in FINAL:                            # settled, but the crash came before the answer was stored
            o = self._outcome(intent, grant, None)
            return o["http"], o["body"]
        if intent["status"] == "cancelling":
            return 202, {"status": "pending", "payment_intent_id": intent["id"], "state": "cancelling",
                         "detail": "This payment is being cancelled. It may already have been accepted by the bank; "
                                   "read /api/payments/" + intent["id"] + " for the outcome."}
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
        if intent["status"] == "cancelled":
            return {"http": 422, "body": {
                "error": "payment_cancelled", "payment_intent_id": intent["id"],
                "error_description": f"cancelled before the bank accepted it ({intent['reason']}). Nothing was paid. "
                                     "A new attempt needs a new Idempotency-Key, and the customer's approval if required."}}
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
            "intent_evidence": ("agent_reported" if intent["basis"] == "grant" and intent.get("instruction") else
                                EVIDENCE.get(intent["basis"], "standing_mandate"))}
        if intent["basis"] == "approval" or intent.get("approval"):
            fields["approval"] = intent["approval"]
        if intent.get("reason_code"):
            fields["reason_code"] = intent["reason_code"]          # why it needed the customer's approval
        if intent.get("instruction"):
            fields["agent_supplied_instruction"] = intent["instruction"]
        return self.receipts.append(grant_id=grant["id"], agent=grant["client_id"], customer=grant["customer"],
                                    action="payment", outcome=outcome,
                                    basis=intent["basis"] if outcome == "allowed" else ("refused" if outcome == "failed" else intent["basis"]),
                                    grant_level=grant["level"], **fields, **kw)
