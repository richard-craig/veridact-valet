"""Valet behaviour tests. Each test builds a fresh in-process bank and agent."""
from __future__ import annotations

import asyncio
import json
import time
from urllib.parse import parse_qs, urlparse

import pytest

from valet.agent.sdk import ValetError
from valet.common.crypto import Key
from valet.common.dpop import make_proof
from valet.harness import BANK, Harness


def run(coro):
    return asyncio.run(coro)


async def err(coro) -> ValetError:
    with pytest.raises(ValetError) as ei:
        await coro
    return ei.value


WATER = ("acc_4821", "Water & Sanitation", "40021187")
POWER = ("acc_4821", "City Power", "30087712")


# ------------------------------------------------------------------ connect
def test_connect_issues_dpop_bound_bill_payer_grant():
    async def t():
        h = Harness()
        gid = await h.connect()
        g = h.bank.store.grant(gid)
        assert g["status"] == "active" and g["level"] == "bill_payer" and g["jkt"] == h.kaya.key.thumbprint
        claims = h.bank.verify_access_token(h.kaya.session.access_token)
        assert claims["cnf"]["jkt"] == h.kaya.key.thumbprint
    run(t())


def test_unverified_agent_refused_at_par():
    async def t():
        h = Harness()
        e = await err(h.agent("copycat", h.copycat_key).start_connect())
        assert e.error == "unauthorized_client"
    run(t())


def test_authorize_without_par_is_refused():
    async def t():
        h = Harness()
        await h.login()
        r = await h.browser.get("/authorize?client_id=kaya&request_uri=urn:ietf:params:oauth:request_uri:made-up")
        assert r.status_code == 400
    run(t())


def test_customer_choice_overrides_what_the_agent_asked_for():
    async def t():
        h = Harness()
        await h.login()
        url, pending = await h.kaya.start_connect("bill_payer")
        _, back = await h.consent(url, level="view_only")
        await h.kaya.finish_connect(back["code"][0], pending, back["state"][0])
        assert {d["type"] for d in h.kaya.session.details} == {"valet_accounts"}
        e = await err(h.kaya.pay(*WATER, "100.00"))
        assert e.error == "insufficient_authorization"
    run(t())


def test_customer_cancel_returns_access_denied():
    async def t():
        h = Harness()
        await h.login()
        url, _ = await h.kaya.start_connect()
        _, back = await h.consent(url, decision="deny")
        assert back["error"] == ["access_denied"]
    run(t())


def test_wrong_pkce_verifier_and_code_reuse_refused():
    async def t():
        h = Harness()
        await h.login()
        url, pending = await h.kaya.start_connect()
        _, back = await h.consent(url)
        good = pending.verifier
        pending.verifier = "wrong-verifier-wrong-verifier-wrong-verifier"
        e = await err(h.kaya.finish_connect(back["code"][0], pending))
        assert e.error == "invalid_grant"
        pending.verifier = good
        await h.kaya.finish_connect(back["code"][0], pending)  # first good use
        e = await err(h.kaya.finish_connect(back["code"][0], pending))
        assert e.error == "invalid_grant"
    run(t())


def test_consent_requires_csrf_token():
    async def t():
        h = Harness()
        await h.login()
        url, _ = await h.kaya.start_connect()
        q = parse_qs(urlparse(url).query)
        r = await h.browser.post("/authorize/decision", data={"client_id": "kaya", "request_uri": q["request_uri"][0],
                                                              "level": "bill_payer", "account": "acc_4821", "decision": "allow"})
        assert r.status_code == 403
    run(t())


# ---------------------------------------------------------------- DPoP
def test_stolen_token_and_replayed_proof_refused():
    async def t():
        h = Harness()
        await h.connect()
        tok, url = h.kaya.session.access_token, BANK + "/api/accounts"
        r = await h.kaya.http.get(url, headers={"Authorization": f"DPoP {tok}", "DPoP": make_proof(Key.generate(), "GET", url, tok)})
        assert r.status_code == 401
        hdrs = {"Authorization": f"DPoP {tok}", "DPoP": make_proof(h.kaya.key, "GET", url, tok)}
        assert (await h.kaya.http.get(url, headers=hdrs)).status_code == 200
        assert (await h.kaya.http.get(url, headers=hdrs)).status_code == 401
        r = await h.kaya.http.get(url, headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 401
    run(t())


# ------------------------------------------------------------ payments
def test_limit_and_beneficiary_rules():
    async def t():
        h = Harness()
        await h.connect(monthly=1_000_00)
        assert (await h.kaya.pay(*WATER, "640.00"))["outcome"] == "paid"
        held = await h.kaya.pay(*WATER, "400.00")             # 640 + 400 > 1,000
        assert held["outcome"] == "approval_pending" and "over the" in held["reason"]
        held = await h.kaya.pay(*POWER, "10.00")               # new recipient, tiny amount
        assert held["outcome"] == "approval_pending" and "not a saved beneficiary" in held["reason"]
        assert h.bank.store.spent(h.kaya.session.grant_id) == 640_00
    run(t())


def test_approval_is_single_use_exact_and_does_not_add_beneficiary():
    async def t():
        h = Harness()
        await h.connect()
        res = await h.kaya.pay(*POWER, "1250.00", "Oct")
        assert (await h.kaya.check_approval(res["auth_req_id"]))["outcome"] == "approval_pending"
        await h.decide(res["auth_req_id"])
        done = await h.kaya.check_approval(res["auth_req_id"])
        assert done["outcome"] == "paid"
        e = await err(h.kaya.call("POST", "/api/payments", h.kaya.approvals[res["auth_req_id"]], token=done["once_token"]))
        assert e.error == "approval_invalid"
        e = await err(h.kaya.check_approval(res["auth_req_id"]))   # second token for the same approval
        assert e.error == "invalid_grant"
        again = await h.kaya.pay(*POWER, "50.00")                   # still a new recipient
        assert again["outcome"] == "approval_pending"
        assert h.bank.store.spent(h.kaya.session.grant_id) == 0     # approvals do not consume the limit
    run(t())


def test_cannot_request_approval_for_an_action_the_bank_did_not_offer():
    async def t():
        h = Harness()
        await h.connect()
        made_up = [{"type": "valet_payment_once", "from": "acc_4821", "to": {"name": "Fraudster", "account": "1"},
                    "amount": {"amount": "9999.00", "currency": "ZAR"}, "reference": ""}]
        e = await err(h.kaya._post_form("/bc-authorize", {"login_hint": h.kaya.session.grant_id,
                                                          "authorization_details": json.dumps(made_up)}))
        assert e.error == "invalid_authorization_details"
    run(t())


def test_expired_approval_and_pending_cap():
    async def t():
        h = Harness()
        await h.connect()
        res = await h.kaya.pay(*POWER, "100.00")
        h.bank.store.x("UPDATE approvals SET expires=? WHERE id=?", time.time() - 1, res["auth_req_id"])
        assert (await h.kaya.check_approval(res["auth_req_id"]))["outcome"] == "expired"
        for amt in ("101.00", "102.00", "103.00"):
            await h.kaya.pay(*POWER, amt)
        e = await err(h.kaya.pay(*POWER, "104.00"))
        assert e.error == "slow_down"
    run(t())


def test_agents_can_never_add_beneficiaries():
    async def t():
        h = Harness()
        await h.connect()
        e = await err(h.kaya.call("POST", "/api/beneficiaries", {"name": "QuickLoans", "account": "9"}))
        assert e.error == "insufficient_authorization"
    run(t())


# ------------------------------------------------------- stop and control
def test_pause_is_immediate_and_cancels_pending_approvals():
    async def t():
        h = Harness()
        gid = await h.connect()
        res = await h.kaya.pay(*POWER, "100.00")
        await h.grant_action(gid, "pause")
        assert (await err(h.kaya.accounts())).error == "grant_paused"
        assert (await h.kaya.check_approval(res["auth_req_id"]))["outcome"] == "declined"
        await h.grant_action(gid, "resume")
        assert await h.kaya.accounts()
    run(t())


def test_revoke_is_final():
    async def t():
        h = Harness()
        gid = await h.connect()
        await h.grant_action(gid, "revoke")
        assert (await err(h.kaya.accounts())).error == "grant_revoked"
        assert (await err(h.kaya.refresh())).error == "invalid_grant"
        from valet.bank.web import csrf_token
        csrf = csrf_token(h.bank, "cus_thandi")              # no Resume button is shown; post it directly anyway
        await h.browser.post(f"/app/agents/{gid}/resume", data={"csrf": csrf})
        assert h.bank.store.grant(gid)["status"] == "revoked"
    run(t())


def test_refresh_rotation_and_reuse_detection():
    async def t():
        h = Harness()
        gid = await h.connect()
        old = h.kaya.session.refresh_token
        await h.kaya.refresh()
        assert h.kaya.session.refresh_token != old
        h.kaya.session.refresh_token = old
        assert (await err(h.kaya.refresh())).error == "invalid_grant"
        assert h.bank.store.grant(gid)["status"] == "paused"
    run(t())


def test_operator_trust_withdrawn_stops_agent():
    async def t():
        h = Harness()
        await h.connect()
        h.bank.registry.set_trust("kaya", False)
        assert (await err(h.kaya.accounts())).error == "agent_untrusted"
        h.bank.registry.set_trust("kaya", True)
        assert await h.kaya.accounts()
    run(t())


def test_grant_expiry():
    async def t():
        h = Harness()
        gid = await h.connect()
        h.bank.store.x("UPDATE grants SET expires=? WHERE id=?", time.time() - 1, gid)
        assert (await err(h.kaya.accounts())).error == "grant_expired"
    run(t())


# ------------------------------------------------------------- receipts
def test_receipts_chain_and_tamper_detection():
    async def t():
        h = Harness()
        await h.connect()
        await h.kaya.pay(*WATER, "640.00")
        await h.kaya.pay(*POWER, "1250.00")
        chain = h.bank.receipts.verify_chain()
        assert chain["ok"] and chain["count"] >= 3
        kinds = [r["basis"] for r in h.bank.receipts.for_grant(h.kaya.session.grant_id)]
        assert {"consent", "grant", "approval_required"} <= set(kinds)
        h.bank.store.x("DELETE FROM receipts WHERE seq=2")
        assert not h.bank.receipts.verify_chain()["ok"]
    run(t())


def test_customer_screens_render():
    async def t():
        h = Harness()
        gid = await h.connect()
        res = await h.kaya.pay(*POWER, "1250.00", "Oct", "Due Friday")
        dash = (await h.browser.get("/app")).text
        assert "Kaya" in dash and "waiting for your decision" in dash
        appr = (await h.browser.get(f"/app/approvals/{res['auth_req_id']}")).text
        assert "R1,250.00" in appr and "New recipient" in appr and "Due Friday" in appr and "written by the agent" in appr
        act = (await h.browser.get(f"/app/agents/{gid}")).text
        assert "Asked you to approve City Power" in act
    run(t())


def test_login_page_and_bad_password():
    async def t():
        h = Harness()
        r = await h.browser.get("/login")
        assert r.status_code == 200 and 'name="password"' in r.text
        r = await h.browser.post("/login", data={"username": "thandi", "password": "wrong", "next": "/app"})
        assert "/app" not in r.headers.get("location", "")
    run(t())
