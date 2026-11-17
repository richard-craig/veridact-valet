"""
Stopping payments (design 0.6, sections 5.1, 5.2 and 9): cancel-or-confirm, pause and revoke while a payment is in
flight, the bank's denylist, an unreachable registry, mandate references, and the startup and readiness checks.

The rule under all of these: the hold on the customer's limit is released only when the bank says the instruction is
dead (a tombstone) or settled. Nothing is released on a timer.
"""
from __future__ import annotations

import asyncio
import time

import pytest

from valet.agent.sdk import ValetError
from valet.harness import Harness
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


def last(h: Harness, gid: str, action: str) -> dict:
    return next(r for r in h.bank.receipts.for_grant(gid) if r["action"] == action)


def body(payee, amount: str) -> dict:
    return {"from_account": payee[0], "to": {"name": payee[1], "account": payee[2]}, "amount": amount, "reference": ""}


# ------------------------------------------------------------ cancel-or-confirm
def test_cancel_or_confirm_releases_on_a_tombstone_and_confirms_what_the_bank_accepted():
    async def t():
        h = Harness(reconcile_after=0)
        gid = await h.connect()
        core = install(h.bank)
        core.mode = "lost_reply"
        paid = await h.kaya.pay(*WATER, "640.00")                      # the bank has it
        core.mode = "lost_request"
        lost = await h.kaya.pay(*SCHOOL, "300.00")                     # the bank never saw it
        core.mode = "ok"
        assert h.bank.payments.reserved(gid) == 940_00
        stopped = h.bank.stop_grant(gid, "revoked", "the customer disconnected the agent")
        assert stopped == {"cancelled": 1, "already_paid": 1, "with_bank": 0}
        assert h.bank.payments.get(paid["payment_intent_id"])["status"] == "confirmed"
        assert h.bank.payments.get(lost["payment_intent_id"])["status"] == "cancelled"
        assert h.bank.payments.reserved(gid) == 0 and h.bank.store.spent(gid) == 640_00
        assert balance(h) == OPENING - 640_00
        # the tombstone is permanent: a late copy of the instruction cannot pay
        late = h.bank.core.real.execute(type("I", (), {"payment_intent_id": lost["payment_intent_id"]})())
        assert late.status == "declined" and late.reason == "cancelled" and balance(h) == OPENING - 640_00
    run(t())


def test_a_cancel_the_bank_does_not_answer_stays_held_and_escalates():
    async def t():
        h = Harness(reconcile_after=0)
        gid = await h.connect()
        core = install(h.bank)
        core.mode = "lost_request"
        lost = await h.kaya.pay(*SCHOOL, "300.00")
        core.mode, core.blind = "ok", True
        assert h.bank.stop_grant(gid, "revoked", "the customer disconnected the agent")["with_bank"] == 1
        assert h.bank.payments.get(lost["payment_intent_id"])["status"] == "cancelling"
        assert h.bank.payments.reserved(gid) == 300_00                  # no answer: still held
        h.bank.payments.escalate_after = 0
        assert h.bank.payments.reconcile()[0]["now"] == "escalated"
        assert h.bank.payments.reserved(gid) == 300_00
        queue = (await h.browser.get("/ops/payments/escalated")).json()
        assert [p["payment_intent_id"] for p in queue["items"]] == [lost["payment_intent_id"]]
        core.blind = False                                              # the bank answers: tombstoned, released
        assert h.bank.payments.reconcile()[0]["now"] == "cancelled"
        assert h.bank.payments.reserved(gid) == 0 and (await h.browser.get("/ops/payments/escalated")).json()["items"] == []
    run(t())


def test_an_adapter_that_cannot_cancel_escalates_and_never_releases():
    async def t():
        h = Harness(reconcile_after=0)
        gid = await h.connect()
        core = install(h.bank)
        core.supports_cancel = False
        core.mode = "lost_request"
        await h.kaya.pay(*SCHOOL, "300.00")
        core.mode = "ok"
        h.bank.payments.escalate_after = 0
        for _ in range(3):
            assert h.bank.payments.reconcile()[0]["now"] == "escalated"
        assert h.bank.payments.reserved(gid) == 300_00 and core.cancels == 0
        assert sum(r["outcome"] == "escalated" for r in h.bank.receipts.for_grant(gid)) == 1    # escalated once
        ready = (await h.browser.get("/readyz")).json()
        assert ready["payments_escalated"] == 1
    run(t())


# ------------------------------------------------------------ pause is the panic button
async def held_for_approval(h: Harness) -> dict:
    held = await h.kaya.pay(*POWER, "1250.00", "Oct")
    assert held["outcome"] == "approval_pending"
    return held


def test_pause_cancels_an_approval_the_customer_already_gave_and_resume_needs_a_new_one():
    async def t():
        h = Harness()
        gid = await h.connect()
        held = await held_for_approval(h)
        await h.decide(held["auth_req_id"])                             # approved, not yet sent
        await h.grant_action(gid, "pause")
        assert h.bank.payments.get(held["payment_intent_id"])["status"] == "cancelled"
        assert h.bank.store.one("SELECT status FROM approvals WHERE id=?", held["auth_req_id"])["status"] == "cancelled"
        assert last(h, gid, "pause")["payments"] == {"cancelled": 1, "already_paid": 0, "with_bank": 0}
        await h.grant_action(gid, "resume")
        assert (await h.kaya.check_approval(held["auth_req_id"]))["outcome"] == "cancelled"  # the old yes is gone
        assert balance(h) == OPENING
        again = await h.kaya.pay(*POWER, "1250.00", "Oct")              # the assistant must ask again
        assert again["outcome"] == "approval_pending" and again["auth_req_id"] != held["auth_req_id"]
    run(t())


def test_pause_cancels_an_approved_payment_even_after_the_one_time_token_was_fetched():
    async def t():
        h = Harness()
        gid = await h.connect()
        held = await held_for_approval(h)
        await h.decide(held["auth_req_id"])
        tok = await h.kaya._post_form("/token", {"grant_type": "urn:openid:params:grant-type:ciba",
                                                 "auth_req_id": held["auth_req_id"]}, dpop=True)
        await h.grant_action(gid, "pause")
        await h.grant_action(gid, "resume")
        e = await err(h.kaya.call("POST", "/api/payments", body(POWER, "1250.00"), token=tok["access_token"],
                                  idempotency_key=held["idempotency_key"]))
        assert e.status in (401, 403, 422) and balance(h) == OPENING
        assert h.bank.store.spent(gid) == 0 and h.bank.payments.reserved(gid) == 0
    run(t())


def test_the_activity_page_says_when_a_payment_was_already_with_the_bank():
    async def t():
        h = Harness()
        gid = await h.connect()
        core = install(h.bank)
        core.mode = "lost_request"
        await h.kaya.pay(*SCHOOL, "300.00")
        core.mode, core.blind = "ok", True
        await h.grant_action(gid, "revoke")
        assert last(h, gid, "revoke")["payments"]["with_bank"] == 1
        page = (await h.browser.get(f"/app/agents/{gid}")).text
        assert "already with the bank" in page
    run(t())


# ------------------------------------------------------------ the bank's denylist
def test_the_denylist_stops_an_agent_on_the_next_request_and_can_be_lifted():
    async def t():
        h = Harness()
        await h.connect()
        assert await h.kaya.accounts()
        r = await h.browser.post("/ops/denylist", json={"kind": "client_id", "value": "kaya", "reason": "incident 41"})
        assert r.status_code == 200
        e = await err(h.kaya.accounts())
        assert e.status == 403 and e.error == "agent_denied"
        await h.browser.delete("/ops/denylist/client_id/kaya")
        assert await h.kaya.accounts()
        h.bank.deny("jkt", h.kaya.key.thumbprint, "key reported stolen")                 # one key, not the agent
        assert (await err(h.kaya.accounts())).error == "agent_denied"
        assert (await h.browser.post("/ops/denylist", json={"kind": "colour", "value": "x"})).status_code == 400
    run(t())


def test_the_denylist_is_checked_again_at_execution():
    async def t():
        h = Harness()
        gid = await h.connect()
        held = await held_for_approval(h)
        await h.decide(held["auth_req_id"])
        intent, grant = h.bank.payments.get(held["payment_intent_id"]), h.bank.store.grant(gid)
        # The race: another node writes the denylist entry after this request passed its checks and before its
        # instruction is sent, and before that node's stop sweep reaches this intent (raw insert, no sweep).
        h.bank.store.x("INSERT INTO denylist VALUES (?,?,?,?)", "operator",
                       h.bank.registry.lookup("kaya").operator, "operator suspended", time.time())
        done = h.bank.payments.execute(intent, grant)                   # a request checked just before the denial
        assert done["status"] == "cancelled" and balance(h) == OPENING and h.bank.payments.reserved(gid) == 0
    run(t())


# ------------------------------------------------------------ registry unreachable
def test_an_unreachable_registry_stops_payments_at_once_and_reads_after_one_more_cache_period():
    async def t():
        h = Harness()
        await h.connect()
        reg = h.bank.registry
        trust = reg.dir / "trust.json"
        good = trust.read_text()
        trust.write_text("{not json")
        reg._loaded = time.time() - reg.cache_s - 1                     # due for a refresh, which fails
        assert await h.kaya.accounts()                                  # reads: the last good copy, for now
        e = await err(h.kaya.pay(*WATER, "640.00"))
        assert e.status == 503 and e.error == "registry_unavailable" and balance(h) == OPENING
        assert (await h.browser.get("/readyz")).json()["registry"]["available"] is False
        reg._loaded = time.time() - 2 * reg.cache_s - 1                 # the last copy is now too old for reads too
        assert (await err(h.kaya.accounts())).error == "registry_unavailable"
        trust.write_text(good)
        assert (await h.kaya.pay(*WATER, "640.00"))["outcome"] == "paid"
    run(t())


# ------------------------------------------------------------ mandate references
def test_intents_and_receipts_carry_the_mandate_id_and_version():
    async def t():
        h = Harness()
        gid = await h.connect()
        paid = await h.kaya.pay(*WATER, "640.00")
        row = h.bank.store.one("SELECT mandate_version FROM payment_intents WHERE id=?", paid["payment_intent_id"])
        assert row["mandate_version"] == 1
        rec = next(r for r in h.bank.receipts.for_grant(gid) if r["action"] == "payment")
        assert rec["mandate"] == {"id": gid, "version": 1}
        assert h.bank.store.grant(gid)["version"] == 1
    run(t())


# ------------------------------------------------------------ readiness
def test_readiness_reports_what_a_go_live_check_asserts():
    async def t():
        h = Harness()
        ready = (await h.browser.get("/readyz")).json()
        assert ready["status"] == "ready" and ready["key_binding"] == "at_consent"
        assert ready["payments_adapter"] == "DemoCore" and ready["adapter_supports_cancel"] is True
        assert ready["registry"] == {"cache_seconds": 60, "available": True} and ready["denylist_entries"] == 0
    run(t())
