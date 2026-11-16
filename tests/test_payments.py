"""
Payment safety on the direct API (design section 5.1): idempotency, payment intents, the locked limit check and hold,
single-use approvals, and what happens when the bank's payment system does not answer.

Valet never executes a payment: it instructs the bank's core banking API. These tests put a misbehaving core in
front of the fictional one to prove a retry, a crash or a timeout can never pay twice.
"""
from __future__ import annotations

import asyncio
import time

import pytest

from valet.agent.sdk import ValetError
from valet.common.dpop import make_proof
from valet.harness import BANK, Harness
from valet.testing.flaky_core import install

WATER = ("acc_4821", "Water & Sanitation", "40021187")
SCHOOL = ("acc_4821", "Sunrise Primary School", "62114930")
POWER = ("acc_4821", "City Power", "30087712")       # not a saved beneficiary
OPENING = 18_430_55


def run(coro):
    return asyncio.run(coro)


async def err(coro) -> ValetError:
    with pytest.raises(ValetError) as ei:
        await coro
    return ei.value


def balance(h: Harness) -> int:
    return h.bank.store.one("SELECT balance FROM accounts WHERE id='acc_4821'")["balance"]


def paid_receipts(h: Harness, gid: str) -> list[dict]:
    return [r for r in h.bank.receipts.for_grant(gid) if r["action"] == "payment" and r["outcome"] == "allowed"]


def body(payee=WATER, amount="640.00", reference="Oct") -> dict:
    return {"from_account": payee[0], "to": {"name": payee[1], "account": payee[2]}, "amount": amount, "reference": reference}


# ------------------------------------------------------------ idempotency
def test_a_payment_needs_an_idempotency_key():
    async def t():
        h = Harness()
        await h.connect()
        tok, url = h.kaya.session.access_token, BANK + "/api/payments"
        r = await h.kaya.http.post(url, json=body(), headers={"Authorization": f"DPoP {tok}",
                                                              "DPoP": make_proof(h.kaya.key, "POST", url, tok)})
        assert r.status_code == 400 and "Idempotency-Key" in r.json()["error_description"]
        assert balance(h) == OPENING
    run(t())


def test_a_retry_with_the_same_key_returns_the_original_outcome_and_never_pays_twice():
    async def t():
        h = Harness()
        gid = await h.connect()
        first = await h.kaya.pay(*WATER, "640.00", "Oct", idempotency_key="water-oct-2026")
        again = await h.kaya.pay(*WATER, "640.00", "Oct", idempotency_key="water-oct-2026")
        assert first["outcome"] == again["outcome"] == "paid"
        assert again["payment_intent_id"] == first["payment_intent_id"] and again["receipt"] == first["receipt"]
        assert again["bank_payment_id"] == first["bank_payment_id"]
        assert balance(h) == OPENING - 640_00 and h.bank.store.spent(gid) == 640_00
        assert len(paid_receipts(h, gid)) == 1
        # a new key is a new payment
        assert (await h.kaya.pay(*WATER, "640.00", "Oct"))["payment_intent_id"] != first["payment_intent_id"]
        assert balance(h) == OPENING - 1280_00
    run(t())


def test_the_same_key_for_a_different_payment_is_refused():
    async def t():
        h = Harness()
        await h.connect()
        await h.kaya.pay(*WATER, "640.00", idempotency_key="water-oct-2026")
        e = await err(h.kaya.pay(*WATER, "64.00", idempotency_key="water-oct-2026"))
        assert e.status == 422 and e.error == "idempotency_key_reused"
        e = await err(h.kaya.pay(*SCHOOL, "640.00", idempotency_key="water-oct-2026"))
        assert e.error == "idempotency_key_reused"
        assert balance(h) == OPENING - 640_00
    run(t())


def test_receipts_name_the_intent_the_key_the_banks_payment_and_the_intent_evidence():
    async def t():
        h = Harness()
        gid = await h.connect()
        res = await h.kaya.pay(*WATER, "640.00", idempotency_key="water-oct-2026")
        rec = paid_receipts(h, gid)[0]
        assert rec["payment_intent"] == res["payment_intent_id"] and rec["idempotency_key"] == "water-oct-2026"
        assert rec["bank_payment_id"] == res["bank_payment_id"]
        assert rec["basis"] == "grant" and rec["intent_evidence"] == "standing_mandate"
        held = await h.kaya.pay(*POWER, "100.00")
        await h.decide(held["auth_req_id"])
        await h.kaya.check_approval(held["auth_req_id"])
        rec = paid_receipts(h, gid)[0]
        assert rec["basis"] == "approval" and rec["intent_evidence"] == "customer_confirmed"
        assert rec["approval"] == held["auth_req_id"] and rec["payment_intent"] == held["payment_intent_id"]
    run(t())


# ------------------------------------------------------------ limits and holds
def test_concurrent_payments_cannot_both_pass_a_limit_only_one_fits_under():
    async def t():
        h = Harness()
        gid = await h.connect(monthly=1_000_00)
        a, b = await asyncio.gather(h.kaya.pay(*WATER, "600.00"), h.kaya.pay(*SCHOOL, "600.00"))
        assert sorted([a["outcome"], b["outcome"]]) == ["approval_pending", "paid"]
        assert h.bank.store.spent(gid) == 600_00 and balance(h) == OPENING - 600_00
    run(t())


def test_money_held_for_an_unconfirmed_payment_counts_against_the_limit():
    async def t():
        h = Harness()
        gid = await h.connect(monthly=1_000_00)
        core = install(h.bank)
        core.mode = "lost_reply"
        first = await h.kaya.pay(*WATER, "600.00", idempotency_key="water-oct-2026")
        assert first["outcome"] == "pending"                           # the bank did not answer: not "failed"
        assert h.bank.store.spent(gid) == 0 and h.bank.payments.reserved(gid) == 600_00
        core.mode = "ok"
        held = await h.kaya.pay(*SCHOOL, "600.00")                     # 600 held + 600 > 1,000
        assert held["outcome"] == "approval_pending" and "over the" in held["reason"]
    run(t())


def test_an_approved_payment_counts_towards_the_month():
    async def t():
        h = Harness()
        gid = await h.connect(monthly=1_000_00)
        held = await h.kaya.pay(*POWER, "700.00")
        await h.decide(held["auth_req_id"])
        assert (await h.kaya.check_approval(held["auth_req_id"]))["outcome"] == "paid"
        assert h.bank.store.spent(gid) == 700_00
        later = await h.kaya.pay(*WATER, "400.00")                     # 700 + 400 > 1,000: later payments see the true spend
        assert later["outcome"] == "approval_pending"
    run(t())


# ------------------------------------------------------------ when the bank does not answer
def test_bank_pays_but_valet_never_hears_then_the_agent_retries():
    """The review's risk scenario: the core executes, Valet fails before recording success, the agent retries."""
    async def t():
        h = Harness()
        gid = await h.connect()
        core = install(h.bank)
        core.mode = "lost_reply"
        first = await h.kaya.pay(*WATER, "640.00", idempotency_key="water-oct-2026")
        assert first["outcome"] == "pending" and first["state"] == "unknown_outcome"
        assert balance(h) == OPENING - 640_00                          # the bank did pay
        assert h.bank.payments.reserved(gid) == 640_00 and h.bank.store.spent(gid) == 0
        again = await h.kaya.pay(*WATER, "640.00", idempotency_key="water-oct-2026")   # bank still silent
        assert again["outcome"] == "pending"
        core.mode = "ok"
        done = await h.kaya.pay(*WATER, "640.00", idempotency_key="water-oct-2026")
        assert done["outcome"] == "paid" and done["payment_intent_id"] == first["payment_intent_id"]
        assert balance(h) == OPENING - 640_00                          # still one payment at the bank
        assert h.bank.store.spent(gid) == 640_00 and h.bank.payments.reserved(gid) == 0
        outcomes = [r["outcome"] for r in h.bank.receipts.for_grant(gid) if r["action"] == "payment"]
        assert outcomes.count("allowed") == 1 and outcomes.count("unknown") == 1
        assert h.bank.receipts.verify_chain()["ok"]
    run(t())


def test_bank_never_receives_the_instruction_then_the_agent_retries():
    async def t():
        h = Harness()
        gid = await h.connect()
        core = install(h.bank)
        core.mode = "lost_request"
        first = await h.kaya.pay(*WATER, "640.00", idempotency_key="water-oct-2026")
        assert first["outcome"] == "pending" and balance(h) == OPENING
        core.mode = "ok"
        done = await h.kaya.pay(*WATER, "640.00", idempotency_key="water-oct-2026")
        assert done["outcome"] == "paid" and balance(h) == OPENING - 640_00 and core.executions == 1
        status = await h.kaya.call("GET", "/api/payments/" + done["payment_intent_id"])
        assert status["state"] == "confirmed" and status["bank_payment_id"] == done["bank_payment_id"]
    run(t())


def test_valet_crashes_between_holding_the_money_and_recording_the_answer():
    """A crash leaves the intent 'executing'. The retry re-sends the same intent id; the bank answers with the original."""
    async def t():
        h = Harness()
        gid = await h.connect()
        first = await h.kaya.pay(*WATER, "640.00", idempotency_key="water-oct-2026")
        # rewind Valet's record to where a crash after the core call would have left it
        with h.bank.store.tx():
            h.bank.store.db.execute("UPDATE payment_intents SET status='executing', outcome=NULL, bank_payment_id=NULL")
            h.bank.store.db.execute("DELETE FROM ledger")
        done = await h.kaya.pay(*WATER, "640.00", idempotency_key="water-oct-2026")
        assert done["outcome"] == "paid" and done["bank_payment_id"] == first["bank_payment_id"]
        assert balance(h) == OPENING - 640_00 and h.bank.store.spent(gid) == 640_00
    run(t())


def test_reconciliation_settles_what_the_bank_knows_and_releases_only_what_it_never_received():
    async def t():
        h = Harness(reconcile_after=0, escalate_after=3600)
        gid = await h.connect()
        core = install(h.bank)
        core.mode = "lost_reply"
        paid = await h.kaya.pay(*WATER, "640.00")                      # paid at the bank; Valet does not know
        core.mode = "lost_request"
        lost = await h.kaya.pay(*SCHOOL, "300.00")                     # never reached the bank
        assert h.bank.payments.reserved(gid) == 940_00
        core.blind = True                                              # the bank is still down: nothing is released
        assert h.bank.payments.reconcile() == [] and h.bank.payments.reserved(gid) == 940_00
        core.mode, core.blind = "ok", False
        r = await h.browser.post("/ops/payments/reconcile")
        assert r.json()["reconciled"] == [{"payment_intent_id": paid["payment_intent_id"], "was": "unknown_outcome",
                                           "now": "confirmed"}]
        assert h.bank.store.spent(gid) == 640_00 and h.bank.payments.reserved(gid) == 300_00   # the other stays held
        h.bank.payments.escalate_after = 0                             # the bank has had long enough: cancel-or-confirm
        assert h.bank.payments.reconcile() == [{"payment_intent_id": lost["payment_intent_id"], "was": "unknown_outcome",
                                                "now": "cancelled"}]   # the bank tombstoned what it never received
        assert h.bank.payments.reserved(gid) == 0 and balance(h) == OPENING - 640_00
        e = await err(h.kaya.call("POST", "/api/payments", body(SCHOOL, "300.00", ""), idempotency_key=lost["idempotency_key"]))
        assert e.error == "payment_cancelled"                          # that intent is over; a new payment needs a new key
        assert core.cancels == 1
    run(t())


def test_a_decline_by_the_bank_releases_the_hold_and_replays_as_a_decline():
    async def t():
        h = Harness()
        gid = await h.connect(monthly=5_000_00)
        h.bank.store.x("UPDATE accounts SET balance=100000 WHERE id='acc_4821'")      # R1,000 in the account
        e = await err(h.kaya.pay(*WATER, "1500.00", idempotency_key="water-big-0001"))
        assert e.status == 422 and e.error == "insufficient_funds"
        assert h.bank.payments.reserved(gid) == 0 and h.bank.store.spent(gid) == 0 and balance(h) == 1_000_00
        h.bank.store.x("UPDATE accounts SET balance=500000 WHERE id='acc_4821'")
        e = await err(h.kaya.pay(*WATER, "1500.00", idempotency_key="water-big-0001"))
        assert e.error == "insufficient_funds" and balance(h) == 5_000_00             # same key: same answer, no debit
        assert (await h.kaya.pay(*WATER, "1500.00"))["outcome"] == "paid"             # new key: a new payment
        failed = [r for r in h.bank.receipts.for_grant(gid) if r["outcome"] == "failed"]
        assert len(failed) == 1 and failed[0]["reason"] == "insufficient_funds"
    run(t())


# ------------------------------------------------------------ single-use approvals
async def approved(h: Harness, amount: str = "1250.00") -> tuple[dict, str, str]:
    """Hold a payment to a new recipient, have the customer approve it, and fetch the one-time token."""
    held = await h.kaya.pay(*POWER, amount, "Oct")
    await h.decide(held["auth_req_id"])
    tok = await h.kaya._post_form("/token", {"grant_type": "urn:openid:params:grant-type:ciba",
                                             "auth_req_id": held["auth_req_id"]}, dpop=True)
    return held, tok["access_token"], held["idempotency_key"]


def test_an_approval_replayed_across_simultaneous_requests_pays_once():
    async def t():
        h = Harness()
        gid = await h.connect()
        held, once, key = await approved(h)
        send = lambda: h.kaya.call("POST", "/api/payments", body(POWER, "1250.00"), token=once, idempotency_key=key)  # noqa: E731
        a, b = await asyncio.gather(send(), send())
        assert a["status"] == b["status"] == "paid" and a["payment_intent_id"] == b["payment_intent_id"]
        assert balance(h) == OPENING - 1250_00 and h.bank.store.spent(gid) == 1250_00
        assert len(paid_receipts(h, gid)) == 1
        e = await err(h.kaya.call("POST", "/api/payments", body(POWER, "1250.00"), token=once))   # under a new key
        assert e.error == "approval_invalid" and balance(h) == OPENING - 1250_00
    run(t())


def test_an_approval_only_finishes_the_payment_the_bank_held():
    async def t():
        h = Harness()
        await h.connect()
        held, once, key = await approved(h)
        # the same recipient and amount requested again under another key is a different payment intent
        other = await h.kaya.pay(*POWER, "1250.00", "Oct", idempotency_key="power-oct-another")
        e = await err(h.kaya.call("POST", "/api/payments", body(POWER, "1250.00"), token=once,
                                  idempotency_key="power-oct-another"))
        assert e.error == "approval_invalid" and "different payment request" in str(e)
        # a changed amount or payee under the right key is refused too
        e = await err(h.kaya.call("POST", "/api/payments", body(POWER, "9250.00"), token=once, idempotency_key=key))
        assert e.error == "approval_invalid"
        assert balance(h) == OPENING and other["outcome"] == "approval_pending"
        done = await h.kaya.call("POST", "/api/payments", body(POWER, "1250.00"), token=once, idempotency_key=key)
        assert done["status"] == "paid" and done["payment_intent_id"] == held["payment_intent_id"]
    run(t())


def test_an_approved_payment_survives_a_silent_bank_without_paying_twice():
    async def t():
        h = Harness()
        gid = await h.connect()
        held, once, key = await approved(h)
        core = install(h.bank)
        core.mode = "lost_reply"
        first = await h.kaya.call("POST", "/api/payments", body(POWER, "1250.00"), token=once, idempotency_key=key)
        assert first["status"] == "pending" and balance(h) == OPENING - 1250_00
        core.mode = "ok"
        done = await h.kaya.call("POST", "/api/payments", body(POWER, "1250.00"), token=once, idempotency_key=key)
        assert done["status"] == "paid" and balance(h) == OPENING - 1250_00 and h.bank.store.spent(gid) == 1250_00
    run(t())


def test_a_mandate_revoked_after_approval_but_before_execution_stops_the_payment():
    async def t():
        h = Harness()
        gid = await h.connect()
        held, once, key = await approved(h)
        await h.grant_action(gid, "revoke")
        e = await err(h.kaya.call("POST", "/api/payments", body(POWER, "1250.00"), token=once, idempotency_key=key))
        assert e.error == "grant_revoked" and balance(h) == OPENING
    run(t())


def test_a_declined_approval_can_be_asked_again_under_the_same_key():
    async def t():
        h = Harness()
        await h.connect()
        held = await h.kaya.pay(*POWER, "100.00", idempotency_key="power-oct-2026")
        await h.decide(held["auth_req_id"], approve=False)
        assert (await h.kaya.check_approval(held["auth_req_id"]))["outcome"] == "declined"
        again = await h.kaya.pay(*POWER, "100.00", idempotency_key="power-oct-2026")
        assert again["outcome"] == "approval_pending" and again["payment_intent_id"] == held["payment_intent_id"]
        await h.decide(again["auth_req_id"])
        assert (await h.kaya.check_approval(again["auth_req_id"]))["outcome"] == "paid"
        assert balance(h) == OPENING - 100_00
    run(t())


# ------------------------------------------------------------ the agent's key is bound at consent (federated mode)
def test_par_must_name_the_agents_key_and_only_that_key_can_redeem_the_code():
    async def t():
        from valet.common.crypto import Key
        h = Harness()
        await h.login()
        e = await err(h.kaya._post_form("/par", {"response_type": "code", "redirect_uri": h.kaya.redirect_uri, "state": "s",
                                                 "code_challenge": "x" * 43, "code_challenge_method": "S256",
                                                 "authorization_details": "[]"}))
        assert e.error == "invalid_request" and "dpop_jkt" in str(e)
        url, pending = await h.kaya.start_connect()
        _, back = await h.consent(url)
        gid = h.bank.store.one("SELECT id, jkt FROM grants")
        assert gid["jkt"] == h.kaya.key.thumbprint                    # bound when the customer consented
        # a stolen code, even with the agent's client credentials, cannot be redeemed with another proof key
        mine, h.kaya.key = h.kaya.key, Key.generate()
        signer = h.kaya._assertion
        h.kaya._assertion = lambda audience=None: _assert_as(h, mine, audience)
        e = await err(h.kaya.finish_connect(back["code"][0], pending, back["state"][0]))
        assert e.error == "invalid_grant" and "bound to at consent" in str(e)
        h.kaya.key, h.kaya._assertion = mine, signer
        await h.kaya.finish_connect(back["code"][0], pending, back["state"][0])   # the right key still can
        assert await h.kaya.accounts()
    run(t())


def _assert_as(h: Harness, key, audience):
    from valet.common.crypto import random_id
    now = int(time.time())
    jwt_ = key.sign({"iss": "kaya", "sub": "kaya", "aud": audience or h.kaya.issuer, "iat": now, "exp": now + 60,
                     "jti": random_id("ca")}, headers={"kid": key.thumbprint})
    return {"client_id": "kaya", "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": jwt_}


def test_the_authorisation_response_names_its_issuer_and_the_agent_checks_it():
    async def t():
        h = Harness()
        await h.login()
        url, pending = await h.kaya.start_connect()
        _, back = await h.consent(url)
        assert back["iss"] == [BANK]                                   # RFC 9207
        e = await err(h.kaya.finish_connect(back["code"][0], pending, back["state"][0], "https://evil.example"))
        assert e.error == "invalid_issuer"
        await h.kaya.finish_connect(back["code"][0], pending, back["state"][0], back["iss"][0])
    run(t())


def test_the_single_use_gate_lets_one_of_two_racing_workers_through():
    """Two bank workers that both passed the approval checks: only one moves the intent to reserved."""
    async def t():
        h = Harness()
        await h.connect()
        held, once, key = await approved(h)
        p, store = h.bank.payments, h.bank.store
        intent = p.get(held["payment_intent_id"])
        consume = "UPDATE approvals SET consumed=1 WHERE id=? AND consumed=0"
        assert store.x(consume, held["auth_req_id"]) == 1 and p.reserve_approved(intent, held["auth_req_id"])
        assert store.x(consume, held["auth_req_id"]) == 0 and not p.reserve_approved(intent, held["auth_req_id"])
        grant = store.grant(intent["grant_id"])
        first, second = p.execute(p.get(intent["id"]), grant), p.execute(p.get(intent["id"]), grant)
        assert first["status"] == second["status"] == "confirmed" and balance(h) == OPENING - 1250_00
        assert store.spent(grant["id"]) == 1250_00                     # settled once, however many workers ask
    run(t())


def test_two_grants_of_the_same_agent_can_use_the_same_idempotency_key():
    """Keys are scoped to the grant: one agent serves many customers, and each may send 'water-oct-2026'."""
    async def t():
        h = Harness()
        first = await h.connect()
        a = await h.kaya.pay(*WATER, "640.00", idempotency_key="water-oct-2026")
        second = await h.connect()
        assert second != first
        b = await h.kaya.pay(*WATER, "64.00", idempotency_key="water-oct-2026")
        assert a["outcome"] == b["outcome"] == "paid" and a["payment_intent_id"] != b["payment_intent_id"]
        assert balance(h) == OPENING - 704_00
    run(t())
