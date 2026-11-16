"""
The boundary between Valet and the bank's payment system.

Valet never executes a payment. It decides whether a payment may go ahead, holds the amount against the mandate, and
hands the bank's core banking API one instruction: "execute payment intent X". The bank executes, clears and settles.

The contract Valet needs from the bank is small (design section 5.1):

  execute(instruction)   Idempotent on instruction.payment_intent_id: the same id never moves money twice, and a
                         repeat returns the original result. Returns "paid" (with the bank's own payment id) or
                         "declined" (with a reason). Raises CoreUnavailable when the outcome is not known: a timeout,
                         a dropped connection, a 5xx. That is not a failure; the payment may have gone through.
  status(id)             What the bank knows about an intent: the same result as execute, or None if it never arrived.
  cancel(id)             Cancel-or-confirm (design section 5.1). Idempotent. Either the bank had already accepted the
                         payment ("already_accepted", with its payment id), or it records a permanent tombstone for the
                         id, so that the instruction is refused if it ever arrives later ("tombstoned"). Raises
                         CoreUnavailable when it cannot say which. Valet releases a hold ONLY on "tombstoned".
  supports_cancel        Whether the adapter can tombstone. An adapter for a core that cannot do it natively enforces
                         the tombstone itself, in the bank-controlled payment API in front of the core. Without it,
                         Valet never releases an unconfirmed payment automatically: it escalates to operations.

DemoCore is Marula Bank's fictional core banking system, kept in the same SQLite file so the PoC runs anywhere. A bank
replaces it with an adapter for its own payments API and passes payment_intent_id as that API's idempotency key.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Protocol

from ..common.crypto import random_id
from .store import Store


class CoreUnavailable(Exception):
    """The bank's payment system did not answer, so the outcome is unknown."""


@dataclass(frozen=True)
class PaymentInstruction:
    payment_intent_id: str        # the idempotency key Valet gives the bank
    customer: str
    from_account: str
    to_name: str
    to_account: str
    cents: int
    reference: str
    by_agent: str


@dataclass(frozen=True)
class CoreResult:
    status: str                   # "paid" or "declined"
    bank_payment_id: str | None = None
    reason: str | None = None     # for "declined": insufficient_funds, unknown_account


@dataclass(frozen=True)
class CancelResult:
    status: str                   # "tombstoned" or "already_accepted"
    bank_payment_id: str | None = None


class CoreBanking(Protocol):
    supports_cancel: bool
    def execute(self, instruction: PaymentInstruction) -> CoreResult: ...
    def status(self, payment_intent_id: str) -> CoreResult | None: ...
    def cancel(self, payment_intent_id: str) -> CancelResult: ...


CORE_SCHEMA = """
CREATE TABLE IF NOT EXISTS core_payments (payment_intent_id TEXT PRIMARY KEY, bank_payment_id TEXT, status TEXT,
    reason TEXT, account TEXT, amount INTEGER, time REAL);
"""


def _result(row: Any) -> CoreResult:
    if row["status"] == "tombstoned":                            # cancelled before it was ever accepted
        return CoreResult("declined", None, "cancelled")
    return CoreResult(row["status"], row["bank_payment_id"], row["reason"])


class DemoCore:
    """Marula Bank's core banking system (fictional). Idempotent on the payment intent id; supports tombstones."""

    supports_cancel = True

    def __init__(self, store: Store):
        self.store = store
        store.db.executescript(CORE_SCHEMA)

    def status(self, payment_intent_id: str) -> CoreResult | None:
        row = self.store.one("SELECT * FROM core_payments WHERE payment_intent_id=?", payment_intent_id)
        return _result(row) if row else None

    def cancel(self, payment_intent_id: str) -> CancelResult:
        with self.store.tx():
            row = self.store.db.execute("SELECT * FROM core_payments WHERE payment_intent_id=?",
                                        (payment_intent_id,)).fetchone()
            if row and row["status"] == "paid":
                return CancelResult("already_accepted", row["bank_payment_id"])
            if not row:                                          # never arrived: refuse it for ever if it does
                self.store.db.execute("INSERT INTO core_payments VALUES (?,?,?,?,?,?,?)",
                                      (payment_intent_id, None, "tombstoned", "cancelled", None, None, time.time()))
            return CancelResult("tombstoned")                    # tombstoned now, earlier, or declined: never paid

    def execute(self, instruction: PaymentInstruction) -> CoreResult:
        i, store = instruction, self.store
        with store.tx():
            seen = store.db.execute("SELECT * FROM core_payments WHERE payment_intent_id=?",
                                    (i.payment_intent_id,)).fetchone()
            if seen:                                             # a repeat, or a tombstone: never a second debit
                return _result(seen)
            acct = store.db.execute("SELECT * FROM accounts WHERE id=? AND customer=?",
                                    (i.from_account, i.customer)).fetchone()
            if not acct:
                result = CoreResult("declined", None, "unknown_account")
            elif acct["balance"] < i.cents:
                result = CoreResult("declined", None, "insufficient_funds")
            else:
                result = CoreResult("paid", random_id("bp", 10))
                store.db.execute("UPDATE accounts SET balance=balance-? WHERE id=?", (i.cents, i.from_account))
                store.db.execute("INSERT INTO transactions (account,time,description,amount,by_agent) VALUES (?,?,?,?,?)",
                                 (i.from_account, time.time(),
                                  f"To {i.to_name}" + (f" ({i.reference})" if i.reference else ""), -i.cents, i.by_agent))
            store.db.execute("INSERT INTO core_payments VALUES (?,?,?,?,?,?,?)",
                             (i.payment_intent_id, result.bank_payment_id, result.status, result.reason,
                              i.from_account, i.cents, time.time()))
            return result
