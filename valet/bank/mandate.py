"""
The mandate check: one function, used by the direct API and the MCP gateway, so both front doors apply the same
profile rules in the same order and give the same reasons (docs/valet-profile.md, sections 3 and 4).

Call it inside store.tx(), together with creating the payment intent, so the check and the hold are one locked step.

Order (the first rule a payment breaks is the reason):
    new_recipient            the payee is not a saved beneficiary
    payee_not_on_mandate     saved, but not one of the payees the customer named
    over_per_payment         above the cap per payment
    over_monthly_count       the month already has the most payments allowed (held ones count)
    over_monthly_limit       the month's total, counting holds, would go over the limit
    approved_payer           the customer approves every payment (approval mode)
    over_approval_threshold  above the amount the customer asked to approve (Bill payer, optional)

A payment that breaks none of them is covered by the standing mandate. On the direct API, a payment that breaks one is
held and offered to the customer for approval (approval_required with the reason). On the MCP gateway, where every
payment is approved anyway, the payee and limit reasons are refusals: an approval there never widens the mandate.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..common.money import rand
from . import levels as L
from .store import Store, month_key

REASONS = ("new_recipient", "payee_not_on_mandate", "over_per_payment", "over_monthly_count", "over_monthly_limit",
           "approved_payer", "over_approval_threshold")
# Reasons an approval may cover on the direct API. Every reason is approvable there; the gateway refuses the first five.
LIMIT_REASONS = REASONS[:5]
# The MCP gateway's reason codes (its three-outcome contract) for the same rules.
MCP_CODES = {"new_recipient": "PAYEE_NOT_IN_MANDATE", "payee_not_on_mandate": "PAYEE_NOT_IN_MANDATE",
             "over_per_payment": "PER_PAYMENT_CAP_EXCEEDED", "over_monthly_count": "MONTHLY_COUNT_REACHED",
             "over_monthly_limit": "MONTHLY_LIMIT_EXCEEDED"}

_COUNTED_SQL = "('confirmed','reserved','executing','unknown_outcome','cancelling')"


@dataclass
class Check:
    covered: bool                 # inside the standing mandate: no approval needed
    reason: str | None = None     # one of REASONS when not covered
    text: str = ""                # the same reason in plain words, for the customer and the agent


def used(store: Store, grant_id: str, month: str | None = None) -> tuple[int, int]:
    """(cents, payments) used this month: confirmed by the bank, or held for it to confirm."""
    month = month or month_key()
    row = store.one(f"SELECT COUNT(*) c FROM payment_intents WHERE grant_id=? AND month=? "
                    f"AND status IN {_COUNTED_SQL}", grant_id, month)
    held = store.one("SELECT COALESCE(SUM(amount),0) n FROM payment_intents WHERE grant_id=? AND month=? AND status IN "
                     "('reserved','executing','unknown_outcome','cancelling')", grant_id, month)["n"]
    return store.spent(grant_id, month) + held, row["c"]


def check_payment(store: Store, grant: dict[str, Any], to_account: str, cents: int,
                  waiting_cents: int = 0, waiting_count: int = 0) -> Check:
    """Is this payment covered by the grant's standing mandate? `waiting_*` adds payments not yet held but already
    asked for (the MCP gateway counts payments waiting for the customer)."""
    details = grant["details"]
    ben = store.one("SELECT id, name FROM beneficiaries WHERE customer=? AND account=?", grant["customer"], to_account)
    if not ben:
        return Check(False, "new_recipient", "this payee is not a saved beneficiary on this account")
    named = L.payees(details)
    if named is not None and ben["id"] not in named:
        return Check(False, "payee_not_on_mandate", f"{ben['name']} is not one of the payees you chose for this agent")
    cap = L.per_payment_cap(details) or 0
    if cents > cap:
        return Check(False, "over_per_payment", f"{rand(cents)} is over the {rand(cap)} limit for a single payment")
    spent, count = used(store, grant["id"])
    spent, count = spent + waiting_cents, count + waiting_count
    most = L.monthly_count(details)
    if most is not None and count >= most:
        return Check(False, "over_monthly_count", f"this month already has {count} of the {most} payments allowed")
    limit = L.monthly_limit(details) or 0
    if spent + cents > limit:
        return Check(False, "over_monthly_limit",
                     f"{rand(cents)} would take this month to {rand(spent + cents)}, over the {rand(limit)} limit")
    if L.approval_mode(details) == "approved_payer":
        return Check(False, "approved_payer", "you approve every payment this agent makes")
    above = L.approve_above(details)
    if above is not None and cents > above:
        return Check(False, "over_approval_threshold", f"you asked to approve payments over {rand(above)}")
    return Check(True)
