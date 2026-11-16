"""A core banking system that misbehaves on demand, for testing what Valet does when the bank does not answer."""
from __future__ import annotations

from ..bank.core import CancelResult, CoreBanking, CoreResult, CoreUnavailable, PaymentInstruction


class FlakyCore:
    """Wraps the real core. `mode`:
       "ok"            behave normally
       "lost_reply"    execute the payment, then fail to answer (the bank paid; Valet never heard)
       "lost_request"  fail before the payment reaches the bank (nothing was paid)
    `blind` makes status() and cancel() fail too, as when the bank's payment system is down.
    `supports_cancel = False` stands in for an adapter that cannot tombstone."""

    def __init__(self, real: CoreBanking):
        self.real, self.mode, self.blind, self.executions = real, "ok", False, 0
        self.supports_cancel, self.cancels = real.supports_cancel, 0

    def cancel(self, payment_intent_id: str) -> CancelResult:
        if self.blind or not self.supports_cancel:
            raise CoreUnavailable("the bank's payment system is not answering")
        self.cancels += 1
        return self.real.cancel(payment_intent_id)

    def execute(self, instruction: PaymentInstruction) -> CoreResult:
        if self.mode == "lost_request":
            raise CoreUnavailable("timed out before the bank received the instruction")
        self.executions += 1
        result = self.real.execute(instruction)
        if self.mode == "lost_reply":
            raise CoreUnavailable("timed out waiting for the bank's answer")
        return result

    def status(self, payment_intent_id: str) -> CoreResult | None:
        if self.blind:
            raise CoreUnavailable("the bank's payment system is not answering")
        return self.real.status(payment_intent_id)


def install(bank) -> FlakyCore:
    """Put a FlakyCore in front of the bank's core banking system."""
    flaky = FlakyCore(bank.core)
    bank.core = bank.payments.core = flaky
    return flaky
