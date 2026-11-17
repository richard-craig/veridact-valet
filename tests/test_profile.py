"""
Conformance tests for the Valet profile (docs/valet-profile.md): one test per approval rule and refusal reason, on both
front doors (the direct API and the MCP gateway), and the receipt format.

A deployment conforms to the profile when these pass against it.
"""
from __future__ import annotations

import asyncio
import json
import time

import pytest

from valet.bank import mandate
from valet.bank.grants import create_grant
from valet.bank.receipts import personal_hash
from valet.bank.tokens import ExternalIssuer
from valet.harness import BANK, Harness
from valet.testing.mock_idp import MockIdP

WATER = ("acc_4821", "Water & Sanitation", "40021187")
SCHOOL = ("acc_4821", "Sunrise Primary School", "62114930")
POWER = ("acc_4821", "City Power", "30087712")       # not a saved beneficiary


def run(coro):
    return asyncio.run(coro)


def held_receipt(h: Harness, gid: str, intent_id: str) -> dict:
    return next(r for r in h.bank.receipts.for_grant(gid) if r.get("payment_intent") == intent_id and r["outcome"] == "held")


async def expect_held(h: Harness, gid: str, payee, amount: str, reason: str) -> dict:
    res = await h.kaya.pay(*payee, amount, "Ref")
    assert res["outcome"] == "approval_pending", res
    assert res["reason_code"] == reason, res
    assert held_receipt(h, gid, res["payment_intent_id"])["reason_code"] == reason
    return res


# ------------------------------------------------------------ the approval rules, in check order
def test_new_recipient():
    async def t():
        h = Harness()
        gid = await h.connect()
        await expect_held(h, gid, POWER, "100.00", "new_recipient")
    run(t())


def test_payee_not_on_mandate():
    async def t():
        h = Harness()
        gid = await h.connect(payees=["ben_water"])
        assert (await h.kaya.pay(*WATER, "100.00", "Ref"))["outcome"] == "paid"
        await expect_held(h, gid, SCHOOL, "100.00", "payee_not_on_mandate")
    run(t())


def test_a_beneficiary_saved_after_consent_is_not_covered():
    async def t():
        h = Harness()
        gid = await h.connect()                                     # payees: the beneficiaries saved at consent
        h.bank.store.x("INSERT INTO beneficiaries VALUES ('ben_new','cus_thandi','Gym','55500011')")
        await expect_held(h, gid, ("acc_4821", "Gym", "55500011"), "100.00", "payee_not_on_mandate")
    run(t())


def test_over_per_payment():
    async def t():
        h = Harness()
        gid = await h.connect(per_payment=500_00)
        assert (await h.kaya.pay(*WATER, "500.00", "Ref"))["outcome"] == "paid"
        await expect_held(h, gid, WATER, "500.01", "over_per_payment")
    run(t())


def test_over_monthly_count():
    async def t():
        h = Harness()
        gid = await h.connect(count=2)
        for _ in range(2):
            assert (await h.kaya.pay(*WATER, "100.00", "Ref"))["outcome"] == "paid"
        await expect_held(h, gid, WATER, "100.00", "over_monthly_count")
    run(t())


def test_over_monthly_limit():
    async def t():
        h = Harness()
        gid = await h.connect(monthly=1_000_00)
        assert (await h.kaya.pay(*WATER, "640.00", "Ref"))["outcome"] == "paid"
        await expect_held(h, gid, WATER, "640.00", "over_monthly_limit")
    run(t())


def test_approved_payer_approves_every_payment():
    async def t():
        h = Harness()
        gid = await h.connect(level="approved_payer")
        assert h.bank.store.grant(gid)["level"] == "approved_payer"
        held = await expect_held(h, gid, WATER, "50.00", "approved_payer")
        await h.decide(held["auth_req_id"])
        paid = await h.kaya.check_approval(held["auth_req_id"])
        assert paid["outcome"] == "paid"
        rec = next(r for r in h.bank.receipts.for_grant(gid) if r.get("payment_intent") == held["payment_intent_id"]
                   and r["outcome"] == "allowed")
        assert rec["basis"] == "approval" and rec["approval"] and rec["reason_code"] == "approved_payer"
    run(t())


def test_over_approval_threshold():
    async def t():
        h = Harness()
        gid = await h.connect(approve_above=500_00)
        assert (await h.kaya.pay(*WATER, "500.00", "Ref"))["outcome"] == "paid"
        await expect_held(h, gid, WATER, "640.00", "over_approval_threshold")
    run(t())


def test_the_first_rule_broken_is_the_reason():
    async def t():
        h = Harness()
        gid = await h.connect(payees=["ben_water"], per_payment=100_00, monthly=500_00)
        # outside the payees, the cap and the limit at once: the payee rule comes first
        await expect_held(h, gid, SCHOOL, "900.00", "payee_not_on_mandate")
        await expect_held(h, gid, WATER, "900.00", "over_per_payment")
    run(t())


def test_an_approval_covers_one_payment_and_counts_towards_the_month():
    async def t():
        h = Harness()
        gid = await h.connect(per_payment=500_00, count=2)
        held = await expect_held(h, gid, WATER, "640.00", "over_per_payment")
        await h.decide(held["auth_req_id"])
        assert (await h.kaya.check_approval(held["auth_req_id"]))["outcome"] == "paid"
        assert (await h.kaya.pay(*WATER, "100.00", "Ref"))["outcome"] == "paid"       # 2 of 2
        await expect_held(h, gid, WATER, "100.00", "over_monthly_count")
        assert mandate.used(h.bank.store, gid) == (740_00, 2)
    run(t())


# ------------------------------------------------------------ what the consent screen may create
def test_payees_must_be_saved_beneficiaries_and_a_paying_level_needs_one():
    h = Harness()
    bank = h.bank
    cus = dict(bank.store.one("SELECT * FROM customers WHERE username='thandi'"))
    kaya = bank.registry.lookup("kaya")
    with pytest.raises(ValueError, match="saved beneficiaries"):
        create_grant(bank, cus, kaya, "bill_payer", "acc_4821", 1_000_00, via="test", payees=["ben_quickloans"])
    with pytest.raises(ValueError, match="at least one payee"):
        create_grant(bank, cus, kaya, "bill_payer", "acc_4821", 1_000_00, via="test", payees=[])
    g = create_grant(bank, cus, kaya, "bill_payer", "acc_4821", 1_000_00, via="test", payees=["ben_water"],
                     per_payment_cents=9_000_00, monthly_count=99)
    p = next(d for d in g["details"] if d["type"] == "valet_payments")
    assert p["payees"] == ["ben_water"] and p["approval"] == "bill_payer"
    assert p["limits"]["per_payment"]["amount"] == "1000.00"            # never above the monthly limit
    assert p["limits"]["per_month"] == {"amount": "1000.00", "currency": "ZAR", "count": bank.cfg.max_monthly_count}


def test_the_consent_screen_offers_the_profile_choices():
    async def t():
        h = Harness()
        await h.login()
        url, _ = await h.kaya.start_connect("bill_payer", intent="Pay my monthly utility bills")
        page = (await h.browser.get(url[url.index("/authorize"):])).text
        for field in ('name="payees"', 'name="per_payment"', 'name="count"', 'name="approve_above"', 'name="intent"',
                      "Pay my monthly utility bills", "Approved payer"):
            assert field in page, field
    run(t())


# ------------------------------------------------------------ the MCP gateway applies the same rules
class Gateway:
    def __init__(self, **choices):
        self.idp = MockIdP(issuer="http://idp.test/realms/marula")
        self.h = Harness(external_issuers={self.idp.issuer: ExternalIssuer(issuer=self.idp.issuer, audience="marula-api",
                                                                            jwks=self.idp.jwks)})
        bank = self.h.bank
        cus = dict(bank.store.one("SELECT * FROM customers WHERE username='thandi'"))
        self.grant = create_grant(bank, cus, bank.registry.lookup("claude"), "bill_payer", "acc_4821",
                                  choices.pop("monthly", 2_000_00), via="test", **choices)
        self.n = 0

    async def tool(self, name: str, **args) -> dict:
        now = int(time.time())
        token = self.idp.sign({"iss": self.idp.issuer, "aud": BANK + "/mcp", "azp": "claude",
                               "sub": "u-1", "iat": now, "exp": now + 300, "valet_grant": self.grant["id"],
                               "scope": "openid"}, typ="at+jwt")
        self.n += 1
        r = await self.h.browser.post("/mcp", json={"jsonrpc": "2.0", "id": self.n, "method": "tools/call",
                                                    "params": {"name": name, "arguments": args}},
                                      headers={"Authorization": f"Bearer {token}"})
        return json.loads(r.json()["result"]["content"][0]["text"])

    async def pay(self, payee: str, amount: str) -> dict:
        self.n += 1
        return await self.tool("pay_existing_payee", payee_id=payee, from_account_id="acc_4821", amount=amount,
                               reference="Ref", reason="Customer asked to pay this bill",
                               idempotency_key=f"mcp-key-{self.n:04d}")


@pytest.mark.parametrize("choices,payee,amount,code", [
    ({"payees": ["ben_water"]}, "ben_school", "100.00", "PAYEE_NOT_IN_MANDATE"),
    ({"per_payment_cents": 500_00}, "ben_water", "640.00", "PER_PAYMENT_CAP_EXCEEDED"),
])
def test_the_gateway_refuses_outside_the_mandate_with_the_same_rules(choices, payee, amount, code):
    async def t():
        g = Gateway(**choices)
        out = await g.pay(payee, amount)
        assert out["outcome"] == "DECLINED" and out["reason_codes"] == [code], out
    run(t())


def test_the_gateway_counts_money_waiting_for_the_customer_against_the_limit():
    async def t():
        g = Gateway(monthly=1_000_00)
        assert (await g.pay("ben_water", "640.00"))["outcome"] == "APPROVAL_REQUIRED"
        assert (await g.pay("ben_water", "640.00"))["reason_codes"] == ["MONTHLY_LIMIT_EXCEEDED"]
    run(t())


def test_the_gateway_counts_payments_waiting_for_the_customer():
    async def t():
        g = Gateway(monthly_count=2)
        assert (await g.pay("ben_water", "100.00"))["outcome"] == "APPROVAL_REQUIRED"
        assert (await g.pay("ben_water", "100.00"))["outcome"] == "APPROVAL_REQUIRED"
        assert (await g.pay("ben_water", "100.00"))["reason_codes"] == ["MONTHLY_COUNT_REACHED"]
    run(t())


def test_the_gateway_lists_only_the_mandates_payees():
    async def t():
        g = Gateway(payees=["ben_water"])
        assert [p["payee_id"] for p in (await g.tool("list_payees"))["payees"]] == ["ben_water"]
    run(t())


# ------------------------------------------------------------ the receipt format
def test_receipts_carry_intent_instruction_reason_and_approval_with_personal_data_outside_the_chain():
    async def t():
        h = Harness()
        gid = await h.connect(intent="Pay my monthly utility bills")
        res = await h.kaya.pay(*POWER, "300.00", "Oct", instruction="Pay the City Power bill from my email")
        await h.decide(res["auth_req_id"])
        assert (await h.kaya.check_approval(res["auth_req_id"]))["outcome"] == "paid"

        rec = next(r for r in h.bank.receipts.for_grant(gid) if r.get("payment_intent") == res["payment_intent_id"]
                   and r["outcome"] == "allowed")
        # what the bank's own screens see
        assert rec["intent"] == "Pay my monthly utility bills"
        assert rec["agent_supplied_instruction"] == "Pay the City Power bill from my email"
        assert rec["reason_code"] == "new_recipient" and rec["approval"]
        # what the chain holds: salted hashes, never the text
        row = h.bank.store.one("SELECT record FROM receipts WHERE seq=?", rec["seq"])
        assert "utility" not in row["record"] and "email" not in row["record"]
        chained = json.loads(row["record"])
        shown = h.bank.receipts.personal(rec["seq"])
        for k in ("intent", "agent_supplied_instruction"):
            assert chained["personal"][k] == personal_hash(shown[k]["value"], shown[k]["salt"])
        # POPIA: erase the values; the chain still verifies and the hashes remain
        assert h.bank.receipts.erase_personal(gid) > 0
        assert h.bank.receipts.verify_chain()["ok"]
        after = next(r for r in h.bank.receipts.for_grant(gid) if r["seq"] == rec["seq"])
        assert "agent_supplied_instruction" not in after and after["personal"] == chained["personal"]
    run(t())


def test_every_reason_has_a_test():
    """Adding a reason to the profile without a conformance test fails here."""
    import sys
    tested = {"new_recipient", "payee_not_on_mandate", "over_per_payment", "over_monthly_count", "over_monthly_limit",
              "approved_payer", "over_approval_threshold"}
    assert set(mandate.REASONS) == tested
    names = {n for n in dir(sys.modules[__name__]) if n.startswith("test_")}
    assert {"test_" + r for r in tested if r != "approved_payer"} <= names


def test_a_payment_inside_the_mandate_with_an_instruction_is_agent_reported():
    async def t():
        h = Harness()
        gid = await h.connect()
        res = await h.kaya.pay(*WATER, "100.00", "Ref", instruction="Pay the water bill")
        assert res["outcome"] == "paid"
        rec = next(r for r in h.bank.receipts.for_grant(gid) if r.get("payment_intent") == res["payment_intent_id"])
        assert rec["intent_evidence"] == "agent_reported" and rec["agent_supplied_instruction"] == "Pay the water bill"
        plain = await h.kaya.pay(*WATER, "100.00", "Ref")
        rec = next(r for r in h.bank.receipts.for_grant(gid) if r.get("payment_intent") == plain["payment_intent_id"])
        assert rec["intent_evidence"] == "standing_mandate"
    run(t())
