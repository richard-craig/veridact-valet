"""
Access levels: named, safe-by-default templates over RAR authorization_details.

The agent may ask for a level; the customer chooses on the consent screen. The grant stores
what the customer chose, never what the agent asked for.
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
    "bill_payer": {
        "title": "Bill payer",
        "summary": "Pay your existing beneficiaries, up to a monthly limit",
        "never": ["Pay someone new without asking you", "Add beneficiaries", "Change your limits",
                  "See card numbers or your password"],
    },
}

MONTHLY_CHOICES = [500_00, 1_000_00, 2_000_00, 5_000_00]


def build_details(level: str, account: str, monthly_cents: int = 2_000_00) -> list[dict[str, Any]]:
    details: list[dict[str, Any]] = [{"type": "valet_accounts", "actions": ["read_balances", "read_transactions"],
                                      "accounts": [account], "history_days": 90}]
    if level == "bill_payer":
        details.append({"type": "valet_payments", "actions": ["pay_existing_beneficiary"], "accounts": [account],
                        "limits": {"per_month": {"amount": to_str(monthly_cents), "currency": CURRENCY}}})
    elif level != "view_only":
        raise ValueError(f"unknown level {level}")
    return details


def requested_level(details: list[dict[str, Any]] | None) -> str:
    """What the agent asked for, used only to preselect the consent screen."""
    types = {d.get("type") for d in (details or [])}
    return "bill_payer" if "valet_payments" in types else "view_only"


def find(details: list[dict[str, Any]], typ: str) -> dict[str, Any] | None:
    return next((d for d in details if d.get("type") == typ), None)


def monthly_limit(details: list[dict[str, Any]]) -> int | None:
    p = find(details, "valet_payments")
    return to_cents(p["limits"]["per_month"]["amount"]) if p else None


def plain_summary(level: str, details: list[dict[str, Any]], account_label: str, days: int) -> str:
    """The exact consent wording; its hash is stored with the grant as consent evidence."""
    if level == "bill_payer":
        return (f"Bill payer: pay existing beneficiaries from {account_label}, up to "
                f"{rand(monthly_limit(details) or 0)} a month, and view balances and transactions, for {days} days.")
    return f"View only: see balances and 90 days of transactions on {account_label}, for {days} days."
