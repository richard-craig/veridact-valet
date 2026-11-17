"""
Evidence (design 0.7, sections 8.2, 8.3 and 9.1): the bank's policy on every receipt, the emergency stop recorded and
sweeping in-flight work, and evidence packs a third party can check offline.

These answer the minimum evidence set a bank's AI-agent control framework asks for: the attempted request, the agent,
the mandate and policy version, the authorisation outcome, what was blocked, when, and what happened as a result.
"""
from __future__ import annotations

import asyncio
import copy
import json

import pytest

from valet.agent.sdk import ValetError
from valet.bank.evidence import build, verify_pack
from valet.bank.policy import Policy
from valet.harness import Harness

WATER = ("acc_4821", "Water & Sanitation", "40021187")
POWER = ("acc_4821", "City Power", "30087712")       # not a saved beneficiary: needs the customer's approval
OPENING = 18_430_55


def run(coro):
    return asyncio.run(coro)


def balance(h: Harness) -> int:
    return h.bank.store.one("SELECT balance FROM accounts WHERE id='acc_4821'")["balance"]


# ------------------------------------------------------------ policy version on every receipt
def test_every_receipt_names_the_policy_in_force_and_the_document_matches_its_hash():
    async def t():
        h = Harness(policy_version="CHG-2026-1182")
        gid = await h.connect()
        await h.kaya.accounts()
        await h.kaya.pay(*WATER, "640.00")
        recs = h.bank.receipts.for_grant(gid)
        assert {r["action"] for r in recs} >= {"connect", "payment"}
        for r in recs:
            assert r["policy"] == {"version": "CHG-2026-1182", "hash": h.bank.policy.hash}
            assert r["mandate"] == {"id": gid, "version": 1}
        stored = h.bank.policy.get(h.bank.policy.hash)
        assert Policy.verify(stored) and stored["document"]["ceilings"]["max_monthly_limit_cents"] == 5_000_00
        assert stored["document"]["profile"].startswith("valet-profile/")
        ready = (await h.browser.get("/readyz")).json()
        assert ready["policy"] == {"version": "CHG-2026-1182", "hash": h.bank.policy.hash, "labelled": True}
        assert h.bank.receipts.verify_chain()["ok"]
    run(t())


def test_an_unlabelled_policy_is_named_by_its_hash_and_readiness_says_so():
    async def t():
        h = Harness()
        ready = (await h.browser.get("/readyz")).json()["policy"]
        assert ready["labelled"] is False and ready["version"].startswith("unlabelled-")
        assert ready["version"][len("unlabelled-"):] in ready["hash"]
    run(t())


def test_a_different_policy_gets_a_different_hash_and_a_tampered_document_is_detected():
    a, b = Harness(), Harness(max_monthly_limit=3_000_00)
    assert a.bank.policy.hash != b.bank.policy.hash
    entry = copy.deepcopy(a.bank.policy.get(a.bank.policy.hash))
    entry["document"]["ceilings"]["max_monthly_limit_cents"] = 50_000_00
    assert not Policy.verify(entry)


# ------------------------------------------------------------ the emergency stop is recorded and sweeps
def test_the_denylist_cancels_approvals_and_held_payments_and_records_the_stop():
    async def t():
        h = Harness()
        gid = await h.connect()
        held = await h.kaya.pay(*POWER, "1250.00", "Oct")               # waiting for the customer
        assert held["outcome"] == "approval_pending"
        r = await h.browser.post("/ops/denylist", json={"kind": "client_id", "value": "kaya",
                                                        "reason": "incident 41", "by": "fraud desk"})
        out = r.json()
        assert r.status_code == 200 and out["grants"] == [gid]
        assert out["stopped"]["grants"] == 1 and out["stopped"]["approvals_cancelled"] == 1
        assert out["stopped"]["cancelled"] == 1 and h.bank.payments.reserved(gid) == 0 and balance(h) == OPENING
        assert h.bank.store.one("SELECT status FROM approvals WHERE id=?", held["auth_req_id"])["status"] == "cancelled"
        # the per-grant receipt and the bank-level receipt, both in the signed chain
        stop = next(x for x in h.bank.receipts.for_grant(gid) if x["action"] == "denylist")
        assert stop["basis"] == "bank" and stop["by"] == "fraud desk" and stop["reason"] == "incident 41"
        assert stop["denylist"] == {"kind": "client_id", "value": "kaya"} and stop["payments"]["cancelled"] == 1
        bank_rec = [json.loads(x["record"]) for x in h.bank.store.q("SELECT record FROM receipts")]
        add = next(x for x in bank_rec if x["action"] == "denylist_add")
        assert add["grants"] == [gid] and add["totals"]["cancelled"] == 1 and add["by"] == "fraud desk"
        # the grant keeps its status; lifting the entry restores access, and the cancelled approval stays cancelled
        assert h.bank.store.grant(gid)["status"] == "active"
        lifted = (await h.browser.delete("/ops/denylist/client_id/kaya")).json()
        assert lifted["was_listed"] is True and lifted["receipt"]
        assert await h.kaya.accounts()
        assert any(x["action"] == "denylist_remove" for x in
                   (json.loads(r["record"]) for r in h.bank.store.q("SELECT record FROM receipts")))
        assert h.bank.receipts.verify_chain()["ok"]
    run(t())


def test_denylisting_an_operator_reaches_every_grant_of_its_agents_and_nothing_else():
    async def t():
        h = Harness()
        gid = await h.connect()
        operator = h.bank.registry.lookup("kaya").operator
        out = h.bank.deny("operator", operator, "operator suspended")
        assert out["grants"] == [gid]
        none = h.bank.deny("operator", "Some Other Operator", "unrelated")
        assert none["grants"] == [] and none["stopped"]["grants"] == 0
        with pytest.raises(ValetError) as e:
            await h.kaya.accounts()
        assert e.value.error == "agent_denied"
    run(t())


# ------------------------------------------------------------ evidence packs
def test_an_evidence_pack_verifies_offline_and_names_everything_a_dispute_needs():
    async def t():
        h = Harness(policy_version="CHG-2026-1182")
        gid = await h.connect()
        await h.kaya.pay(*WATER, "640.00")
        h.bank.deny("client_id", "kaya", "incident 41")
        r = await h.browser.get(f"/ops/evidence?grant_id={gid}&reason=dispute D-77")
        assert r.status_code == 200
        pack = r.json()
        result = verify_pack(pack, trusted_jwk=h.bank.receipt_key.jwk)
        assert result["ok"], result["problems"]
        assert result["key"] == "trusted" and result["receipts_checked"] >= 3
        actions = [x["record"]["action"] for x in pack["receipts"]]
        assert {"connect", "payment", "denylist", "denylist_add"} <= set(actions)
        assert [p["version"] for p in pack["policies"]] == ["CHG-2026-1182"]
        assert pack["payment_intents"][0]["status"] == "confirmed"
        assert pack["denylist"] == [{"kind": "client_id", "value": "kaya", "reason": "incident 41",
                                     "added": pack["denylist"][0]["added"]}]
        assert pack["chain"]["check_at_export"]["ok"] and pack["reason"] == "dispute D-77"
        assert (await h.browser.get("/ops/evidence?grant_id=g_nope")).status_code == 404
    run(t())


def test_a_changed_receipt_policy_or_pack_is_caught_and_a_foreign_key_is_refused():
    async def t():
        h = Harness()
        gid = await h.connect()
        await h.kaya.pay(*WATER, "640.00")
        pack = build(h.bank, grant_id=gid)
        key = h.bank.receipt_key.jwk

        edited = copy.deepcopy(pack)
        pay = next(x for x in edited["receipts"] if x["record"]["action"] == "payment")
        pay["record"]["detail"]["amount"] = "6400.00"                   # the classic dispute edit
        problems = verify_pack(edited, trusted_jwk=key)["problems"]
        assert any("record was altered" in p for p in problems) and any(p.startswith("pack") for p in problems)

        swapped = copy.deepcopy(pack)
        swapped["policies"][0]["document"]["ceilings"]["max_monthly_limit_cents"] = 50_000_00
        assert any("does not match its hash" in p for p in verify_pack(swapped, trusted_jwk=key)["problems"])

        dropped = copy.deepcopy(pack)
        dropped["policies"] = []
        assert any("does not include" in p for p in verify_pack(dropped, trusted_jwk=key)["problems"])

        other = Harness().bank.receipt_key.jwk                           # someone else's key
        assert not verify_pack(pack, trusted_jwk=other)["ok"]
        assert verify_pack(pack)["key"].startswith("pack's own copy")
    run(t())


def test_an_evidence_pack_for_an_agent_covers_all_its_grants():
    async def t():
        h = Harness()
        gid = await h.connect()
        pack = build(h.bank, client_id="kaya")
        assert [g["id"] for g in pack["grants"]] == [gid]
        assert verify_pack(pack, trusted_jwk=h.bank.receipt_key.jwk)["ok"]
    run(t())


def test_ops_errors_return_fixed_messages_never_exception_text():
    async def t():
        h = Harness()
        missing = await h.browser.get("/ops/evidence?grant_id=g_nope")
        assert missing.status_code == 404 and missing.json() == {"error": "no_matching_grant",
                                                                 "error_description": "no grant matches"}
        unscoped = await h.browser.get("/ops/evidence")
        assert unscoped.status_code == 404 and unscoped.json()["error"] == "scope_required"
        bad = await h.browser.post("/ops/denylist", json={"kind": "colour", "value": "x"})
        assert bad.status_code == 400 and bad.json()["error"] == "invalid_request"
    run(t())
