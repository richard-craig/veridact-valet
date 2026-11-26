"""
Access levels: named, safe-by-default templates over RAR authorization_details (docs/valet-profile.md).

The agent may ask for a level; the customer chooses on the consent screen. The grant stores
what the customer chose, never what the agent asked for.

A valet_payments detail carries the profile's named constraints:
    payees                     beneficiary ids the customer named at consent (fixed: a beneficiary added later is not covered)
    limits.per_payment         the largest single payment
    limits.per_month.amount    the month's total, counting what is held for unconfirmed payments
    limits.per_month.count     the most payments a month, counting held ones
    limits.approve_above       optional: payments above this amount are offered to the customer for approval
    approval                   "approved_payer" (every payment approved in the bank app) or "bill_payer"
Every detail carries the mandate's `intent`, a plain-language purpose copied into every receipt.
"""
from __future__ import annotations

from typing import Any

from ..common.money import CURRENCY, rand, to_cents, to_str

LEVELS = {
    "view_only": {
        "title": "View only",
        "summary": "See balances and 90 days of transactions",
        "never": ["Move money", "Add beneficiaries", "Change your limits", "See card numbers or your password"],
    },
    "approved_payer": {
        "title": "Approved payer",
        "summary": "Prepare payments to the payees you choose; you approve every one in this app",
        "never": ["Pay anyone without your approval", "Add beneficiaries", "Change your limits",
                  "See card numbers or your password"],
    },
    "bill_payer": {
        "title": "Bill payer",
        "summary": "Pay the payees you choose, within your limits, without asking each time",
        "never": ["Pay someone new without asking you", "Add beneficiaries", "Change your limits",
                  "See card numbers or your password"],
    },
}
PAYING = ("approved_payer", "bill_payer")

MONTHLY_CHOICES = [500_00, 1_000_00, 2_000_00, 5_000_00]
PER_PAYMENT_CHOICES = [250_00, 500_00, 1_000_00, 2_000_00, 5_000_00]
COUNT_CHOICES = [1, 2, 4, 6, 10]
APPROVE_ABOVE_CHOICES = [0, 250_00, 500_00, 1_000_00]          # 0: no threshold

INTENT_MAX = 140


def clean_intent(text: Any) -> str | None:
    s = " ".join(str(text or "").split())[:INTENT_MAX]
    return s or None


def build_details(level: str, account: str, monthly_cents: int = 2_000_00, *, payees: list[str] | None = None,
                  per_payment_cents: int | None = None, monthly_count: int = 10,
                  approve_above_cents: int | None = None, intent: str | None = None) -> list[dict[str, Any]]:
    details: list[dict[str, Any]] = [{"type": "valet_accounts", "actions": ["read_balances", "read_transactions"],
                                      "accounts": [account], "history_days": 90}]
    if level in PAYING:
        per_payment = min(per_payment_cents or monthly_cents, monthly_cents)
        limits: dict[str, Any] = {
            "per_payment": {"amount": to_str(per_payment), "currency": CURRENCY},
            "per_month": {"amount": to_str(monthly_cents), "currency": CURRENCY, "count": int(monthly_count)}}
        if level == "bill_payer" and approve_above_cents:
            limits["approve_above"] = {"amount": to_str(approve_above_cents), "currency": CURRENCY}
        details.append({"type": "valet_payments", "actions": ["pay_existing_beneficiary"], "accounts": [account],
                        "payees": list(payees or []), "approval": level, "limits": limits})
    elif level != "view_only":
        raise ValueError(f"unknown level {level}")
    if intent:
        for d in details:
            d["intent"] = intent
    return details


def consent_choices(form: Any) -> dict[str, Any]:
    """The customer's payment choices from a consent form, as create_grant keyword arguments. A form that showed the
    payee list but has none ticked gives an empty list (refused for paying levels), never "all beneficiaries"."""
    def num(name: str) -> int | None:
        v = str(form.get(name) or "").strip()
        return int(v) if v.isdigit() and int(v) > 0 else None
    shown = bool(form.get("payees_shown"))
    chosen = [str(p) for p in form.getlist("payees")] if hasattr(form, "getlist") else []
    return {"payees": chosen if shown else None, "per_payment_cents": num("per_payment"),
            "monthly_count": num("count"), "approve_above_cents": num("approve_above"),
            "intent": clean_intent(form.get("intent"))}


def consent_options(cfg: Any) -> dict[str, Any]:
    """The choices a consent screen offers, within the bank's ceilings."""
    return {"monthly_choices": [(c, rand(c)) for c in MONTHLY_CHOICES if c <= cfg.max_monthly_limit],
            "per_payment_choices": [(c, rand(c)) for c in PER_PAYMENT_CHOICES if c <= cfg.max_monthly_limit],
            "count_choices": [c for c in COUNT_CHOICES if c <= cfg.max_monthly_count],
            "approve_above_choices": [(c, rand(c)) for c in APPROVE_ABOVE_CHOICES if c <= cfg.max_monthly_limit]}


def requested_level(details: list[dict[str, Any]] | None) -> str:
    """What the agent asked for, used only to preselect the consent screen."""
    p = find(details or [], "valet_payments")
    if not p:
        return "view_only"
    return "bill_payer" if p.get("approval") == "bill_payer" else "approved_payer"


def requested_intent(details: list[dict[str, Any]] | None) -> str | None:
    """The purpose the agent stated, shown on the consent screen for the customer to keep or change."""
    return next((clean_intent(d.get("intent")) for d in (details or []) if d.get("intent")), None)


def within(level: str, ceiling: str | None) -> bool:
    """Is this access level at or below the agent tier's ceiling?"""
    order = list(LEVELS)
    return ceiling is None or order.index(level) <= order.index(ceiling)


def find(details: list[dict[str, Any]], typ: str) -> dict[str, Any] | None:
    return next((d for d in details if d.get("type") == typ), None)


def intent_of(details: list[dict[str, Any]]) -> str | None:
    return next((d["intent"] for d in details if d.get("intent")), None)


def _cents(limits: dict[str, Any], *path: str) -> int | None:
    v: Any = limits
    for p in path:
        v = v.get(p) if isinstance(v, dict) else None
    return to_cents(v) if v is not None else None


def monthly_limit(details: list[dict[str, Any]]) -> int | None:
    p = find(details, "valet_payments")
    return _cents(p["limits"], "per_month", "amount") if p else None


def per_payment_cap(details: list[dict[str, Any]]) -> int | None:
    p = find(details, "valet_payments")
    return (_cents(p["limits"], "per_payment", "amount") or monthly_limit(details)) if p else None


def monthly_count(details: list[dict[str, Any]]) -> int | None:
    p = find(details, "valet_payments")
    c = p["limits"]["per_month"].get("count") if p else None
    return int(c) if c else None


def approve_above(details: list[dict[str, Any]]) -> int | None:
    p = find(details, "valet_payments")
    return _cents(p["limits"], "approve_above", "amount") if p else None


def approval_mode(details: list[dict[str, Any]]) -> str | None:
    p = find(details, "valet_payments")
    return (p.get("approval") or "bill_payer") if p else None


def payees(details: list[dict[str, Any]]) -> list[str] | None:
    """The mandate's payees, or None for a grant made before payees were named (any saved beneficiary)."""
    p = find(details, "valet_payments")
    return list(p["payees"]) if p and "payees" in p else None


def plain_summary(level: str, details: list[dict[str, Any]], account_label: str, days: int,
                  payee_names: list[str] | None = None) -> str:
    """The exact consent wording; its hash is stored with the grant as consent evidence."""
    if level in PAYING:
        who = ", ".join(payee_names) if payee_names else "your saved beneficiaries"
        count = monthly_count(details)
        limits = (f"up to {rand(per_payment_cap(details) or 0)} a payment, "
                  f"{f'at most {count} payments and ' if count else ''}{rand(monthly_limit(details) or 0)} a month")
        if level == "approved_payer":
            how = "You approve every payment in the bank app."
        else:
            above = approve_above(details)
            how = (f"You approve any payment over {rand(above)}, and anything outside these limits, in the bank app."
                   if above else "Anything outside these limits needs your approval in the bank app.")
        title = LEVELS[level]["title"]
        purpose = f" Purpose: {intent_of(details)}." if intent_of(details) else ""
        return (f"{title}: pay {who} from {account_label}, {limits}, and view balances and transactions, "
                f"for {days} days. {how}{purpose}")
    purpose = f" Purpose: {intent_of(details)}." if intent_of(details) else ""
    return f"View only: see balances and 90 days of transactions on {account_label}, for {days} days.{purpose}"
