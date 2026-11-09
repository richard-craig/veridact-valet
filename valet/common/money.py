"""Money as integer cents. Amounts travel as strings ("1250.00") in ZAR."""
from __future__ import annotations

from decimal import ROUND_HALF_UP, Decimal, InvalidOperation

CURRENCY = "ZAR"


def to_cents(amount: str | int | float | Decimal) -> int:
    try:
        d = Decimal(str(amount)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except InvalidOperation as e:
        raise ValueError(f"not an amount: {amount!r}") from e
    if d <= 0:
        raise ValueError("amount must be positive")
    return int(d * 100)


def to_str(cents: int) -> str:
    return f"{cents // 100}.{cents % 100:02d}"


def rand(cents: int) -> str:
    """R1,250.00 style, for people."""
    return f"R{cents // 100:,}.{cents % 100:02d}"
