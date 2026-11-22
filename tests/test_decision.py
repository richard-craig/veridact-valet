"""
The Valet decision service (docs/decision-service.md): AuthZEN evaluation, AARP approvals and reservations, and the
bank's MCP server as the enforcement point that asks it, in-process and over HTTP.
"""
from __future__ import annotations

import asyncio
import json
import time

import httpx
import pytest

from valet.bank import mcp
from valet.decision.client import DecisionUnavailable, HttpDecisions, InProcessDecisions

from test_mcp import World, run

SECRET = "decision-secret-for-tests-0123456789"


@pytest.fixture
def world(monkeypatch):
    monkeypatch.setenv("VALET_DECISION_SECRET", SECRET)
    return World()


def pep(w: World) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=w.h.transport, base_url="http://bank.test",
                             headers={"Authorization": f"Bearer {SECRET}"})


def ask(w: World, action: str, **context) -> dict:
    return {"subject": {"type": "identity", "id": "u-1"}, "action": {"name": action},
            "resource": context.pop("resource", {}),
            "context": {"agent": "claude", "valet_grant": w.grant["id"], "token_tier": "bearer", "channel": "mcp",
                        **context}}


def test_metadata_is_public_and_the_endpoints_are_for_the_bank_only(world):
    async def t():
        w = world
        meta = (await w.h.browser.get("/.well-known/authzen-configuration")).json()
        assert meta["access_evaluation_endpoint"].endswith("/access/v1/evaluation")
        assert meta["access_request_endpoint"] and meta["valet_reservations_endpoint"]
        anon = await w.h.browser.post("/access/v1/evaluation", json=ask(w, "list_accounts"))
        assert anon.status_code == 401
        wrong = await w.h.browser.post("/access/v1/evaluation", json=ask(w, "list_accounts"),
                                       headers={"Authorization": "Bearer nope"})
        assert wrong.status_code == 401
        async with pep(w) as c:
            bad = await c.post("/access/v1/evaluation", content="{", headers={"Content-Type": "application/json"})
            assert bad.status_code == 400
            unknown = await c.post("/access/v1/evaluation", json=ask(w, "transfer_everything"))
            assert unknown.status_code == 400
    run(t())


def test_the_http_interface_is_off_without_a_secret(monkeypatch):
    async def t():
        monkeypatch.delenv("VALET_DECISION_SECRET", raising=False)
        w = World()
        r = await w.h.browser.post("/access/v1/evaluation", json=ask(w, "list_accounts"),
                                   headers={"Authorization": "Bearer "})
        assert r.status_code == 404
    run(t())


def test_reads_are_permits_with_constraints_and_denies_are_decisions_not_errors(world):
    async def t():
        w = world
        async with pep(w) as c:
            ok = (await c.post("/access/v1/evaluation", json=ask(w, "list_accounts"))).json()
            assert ok["decision"] is True and ok["context"]["valet"]["outcome"] == "allowed"
            assert ok["context"]["valet"]["constraints"]["accounts"] == ["acc_4821"]
            other = await c.post("/access/v1/evaluation",
                                 json=ask(w, "get_balance", resource={"type": "account", "id": "acc_9907"}))
            assert other.status_code == 200 and other.json()["decision"] is False
            assert other.json()["context"]["reason"] == "account_not_on_mandate"
            stranger = dict(ask(w, "list_accounts"))
            stranger["context"] = {**stranger["context"], "agent": "kaya"}
            assert (await c.post("/access/v1/evaluation", json=stranger)).json()["context"]["reason"] == "unknown_mandate"
            w.h.bank.store.set_status(w.grant["id"], "paused")
            batch = (await c.post("/access/v1/evaluations", json={
                "subject": {"type": "identity", "id": "u-1"},
                "context": ask(w, "list_accounts")["context"],
                "evaluations": [{"action": {"name": "list_accounts"}}, {"action": {"name": "pay_existing_payee"}}]})).json()
            assert [e["decision"] for e in batch["evaluations"]] == [False, False]
            assert batch["evaluations"][0]["context"]["reason"] == "mandate_paused"
    run(t())


def test_a_payment_is_held_approved_reserved_sent_and_committed_once(world):
    async def t():
        w = world
        pay = ask(w, "pay_existing_payee", resource={"type": "account", "id": "acc_4821"},
                  payment={"payee": "ben_water", "amount": "640.00", "currency": "ZAR"},
                  idempotency_key="water-0001", agent_reason="Water bill")
        async with pep(w) as c:
            held = (await c.post("/access/v1/evaluation", json=pay)).json()
            # a requestable denial (AARP): the bearer tier means the customer approves every payment
            assert held["decision"] is False and held["context"]["reason"] == "bearer_tier"
            rid = held["context"]["valet"]["reservation"]
            again = (await c.post("/access/v1/evaluation", json=pay)).json()
            assert again["context"]["valet"]["reservation"] == rid                       # a retry holds nothing new
            changed = dict(pay, context={**pay["context"], "payment": {"payee": "ben_water", "amount": "641.00"}})
            assert (await c.post("/access/v1/evaluation", json=changed)).json()["context"]["reason"] == \
                "idempotency_key_reused"
            task = await c.post("/access/v1/access_requests",
                                json={"binding_token": held["context"]["access_request"]["binding_token"]})
            assert task.status_code == 202 and task.json()["status"] == "pending"
            tid = task.json()["id"]
            assert (await c.post("/access/v1/access_requests", json={"binding_token": "forged"})).status_code == 400
            early = dict(pay, context={**pay["context"], "approval": {"id": tid}})
            assert (await c.post("/access/v1/evaluation", json=early)).json()["context"]["reason"] == "approval_pending"
            assert (await c.post(f"/valet/v1/reservations/{rid}/sent")).status_code == 409   # not approved yet
            await w.h.login()
            await w.h.decide(tid, approve=True)
            assert (await c.get(f"/access/v1/access_requests/{tid}")).json()["status"] == "approved"
            go = (await c.post("/access/v1/evaluation", json=early)).json()
            assert go["decision"] is True and go["context"]["valet"]["outcome"] == "reserved"
            reuse = (await c.post("/access/v1/evaluation", json=early)).json()
            assert reuse["decision"] is False and reuse["context"]["reason"] == "approval_expired"     # single use
            first, second = (await c.post(f"/valet/v1/reservations/{rid}/sent")).json(), \
                (await c.post(f"/valet/v1/reservations/{rid}/sent")).json()
            assert first["claimed"] is True and second["claimed"] is False and first["state"] == "sent"
            done = (await c.post(f"/valet/v1/reservations/{rid}/commit", json={"bank_payment_id": "bp_1"})).json()
            assert done["state"] == "committed" and done["first"] is True and done["receipt"]
            again = (await c.post(f"/valet/v1/reservations/{rid}/commit", json={"bank_payment_id": "bp_1"})).json()
            assert again["first"] is False
            assert (await c.post(f"/valet/v1/reservations/{rid}/release", json={})).status_code == 409
        assert w.h.bank.store.spent(w.grant["id"]) == 640_00
        assert w.h.bank.receipts.verify_chain()["ok"]
    run(t())


def test_a_declined_or_unsent_reservation_is_released_and_cannot_be_committed(world):
    async def t():
        w = world
        bank = w.h.bank
        async with pep(w) as c:
            for key in ("tv-0000001", "tv-0000002"):
                pay = ask(w, "pay_existing_payee", resource={"type": "account", "id": "acc_4821"},
                          payment={"payee": "ben_dstv", "amount": "100.00"}, idempotency_key=key, agent_reason="TV")
                held = (await c.post("/access/v1/evaluation", json=pay)).json()
                rid = held["context"]["valet"]["reservation"]
                task = (await c.post("/access/v1/access_requests",
                                     json={"binding_token": held["context"]["access_request"]["binding_token"]})).json()
                await w.h.login()
                await w.h.decide(task["id"], approve=True)
                await c.post("/access/v1/evaluation", json=dict(pay, context={**pay["context"],
                                                                              "approval": {"id": task["id"]}}))
                if key.endswith("1"):                            # never sent: released at once
                    out = (await c.post(f"/valet/v1/reservations/{rid}/release", json={"reason": "not_sent"})).json()
                else:                                             # sent, and the bank declined it
                    await c.post(f"/valet/v1/reservations/{rid}/sent")
                    out = (await c.post(f"/valet/v1/reservations/{rid}/release",
                                        json={"reason": "insufficient_funds"})).json()
                    assert out["release_reason"] == "insufficient_funds"
                assert out["state"] == "released"
                assert (await c.post(f"/valet/v1/reservations/{rid}/commit",
                                     json={"bank_payment_id": "bp_x"})).status_code == 409
        assert bank.payments.reserved(w.grant["id"]) == 0 and bank.store.spent(w.grant["id"]) == 0
    run(t())


def test_the_mcp_server_works_the_same_when_it_asks_valet_over_http(world):
    """The sidecar shape: the bank's MCP server reaches Valet over the network, as a separate service."""
    async def t():
        w = world
        w.h.bank.decisions = HttpDecisions("http://bank.test", SECRET, transport=w.h.transport)
        assert (await w.tool("list_accounts"))["accounts"]
        held = await w.tool("pay_existing_payee", payee_id="ben_water", from_account_id="acc_4821", amount="640.00",
                            reason="Water bill", idempotency_key="water-0001")
        assert held["outcome"] == "APPROVAL_REQUIRED"
        await w.h.login()
        await w.h.decide(held["payment_ref"], approve=True)
        paid = await w.tool("get_payment_status", payment_ref=held["payment_ref"])
        assert paid["outcome"] == "APPROVED" and paid["status"] == "paid" and paid["receipt"]
        log = list(w.h.bank.decision_service.log)
        assert {e["call"] for e in log} >= {"evaluation", "access_request", "sent", "commit"}
    run(t())


def test_the_mcp_server_fails_closed_when_valet_cannot_answer(world):
    async def t():
        w = world
        held = await w.tool("pay_existing_payee", payee_id="ben_water", from_account_id="acc_4821", amount="640.00",
                            reason="Water bill", idempotency_key="water-0001")
        await w.h.login()
        await w.h.decide(held["payment_ref"], approve=True)

        def down(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectTimeout("no answer")
        w.h.bank.decisions = HttpDecisions("http://valet.internal", SECRET, transport=httpx.MockTransport(down))
        for method, params in (("tools/list", {}),
                               ("tools/call", {"name": "get_payment_status", "arguments": {"payment_ref": held["payment_ref"]}})):
            r = (await w.rpc(method, params)).json()
            assert r["error"]["code"] == -32603
        assert w.h.bank.store.one("SELECT balance FROM accounts WHERE id='acc_4821'")["balance"] == 18_430_55

        def odd(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"decision": True, "context": {}})    # a permit it cannot understand
        w.h.bank.decisions = HttpDecisions("http://valet.internal", SECRET, transport=httpx.MockTransport(odd))
        r = (await w.rpc("tools/call", {"name": "list_accounts", "arguments": {}})).json()
        assert r["error"]["code"] == -32603
    run(t())


def test_every_tool_publishes_a_mapping_that_projects_every_argument():
    """The PEP conformance rule (docs/decision-service.md): an argument the mapping leaves out is unchecked."""
    for name in mcp.TOOLS:
        assert mcp.unprojected(name) == [], name
    assert "x-authzen-mapping" not in json.dumps(mcp.TOOLS)         # published in _meta, not in the JSON Schema


def test_tools_list_publishes_the_mapping_and_the_directory_annotations(world):
    async def t():
        w = world
        tools = (await w.rpc("tools/list")).json()["result"]["tools"]
        for x in tools:
            assert x["title"] and len(x["name"]) <= 64
            assert ("readOnlyHint" in x["annotations"]) and ("destructiveHint" in x["annotations"])
            assert x["_meta"][mcp.MAPPING_META]["action"]["name"] == x["name"]
    run(t())


def test_a_token_whose_actor_is_not_its_client_is_refused(world):
    async def t():
        w = world
        now = int(time.time())
        good = w.idp.sign({"iss": w.idp.issuer, "aud": w.h.bank.cfg.issuer + "/mcp", "azp": "claude", "sub": "u-1",
                           "iat": now, "exp": now + 300, "valet_grant": w.grant["id"], "act": {"sub": "claude"}},
                          typ="at+jwt")
        bad = w.idp.sign({"iss": w.idp.issuer, "aud": w.h.bank.cfg.issuer + "/mcp", "azp": "claude", "sub": "u-1",
                          "iat": now, "exp": now + 300, "valet_grant": w.grant["id"], "act": {"sub": "kaya"}},
                         typ="at+jwt")
        assert (await w.rpc("tools/list", token=good)).status_code == 200
        assert (await w.rpc("tools/list", token=bad)).status_code == 401
        await w.rpc("tools/call", {"name": "list_accounts", "arguments": {}}, token=good)
        last = w.h.bank.receipts.for_grant(w.grant["id"])[0]
        assert last["act"] == {"sub": "claude"} and last["decided_by"] == "valet_decision_service"
    run(t())


def test_the_read_only_profile_hides_payment_tools(monkeypatch):
    async def t():
        monkeypatch.setenv("VALET_MCP_READ_ONLY", "1")
        w = World()
        names = [x["name"] for x in (await w.rpc("tools/list")).json()["result"]["tools"]]
        assert names == ["list_accounts", "get_balance", "list_transactions", "list_payees"]
        r = await w.tool("pay_existing_payee", payee_id="ben_water", from_account_id="acc_4821", amount="1.00",
                         reason="x", idempotency_key="k-00000001")
        assert r["reason_codes"] == ["TOOL_NOT_IN_MANDATE"]
    run(t())


def test_two_payments_at_once_cannot_both_pass_a_limit_only_one_fits_under(world):
    async def t():
        w = world
        a, b = await asyncio.gather(
            w.tool("pay_existing_payee", payee_id="ben_water", from_account_id="acc_4821", amount="1200.00",
                   reason="water", idempotency_key="water-0001"),
            w.tool("pay_existing_payee", payee_id="ben_school", from_account_id="acc_4821", amount="1200.00",
                   reason="school", idempotency_key="school-001"))
        outcomes = sorted([a["outcome"], b["outcome"]])
        assert outcomes == ["APPROVAL_REQUIRED", "DECLINED"]
        assert "MONTHLY_LIMIT_EXCEEDED" in (a.get("reason_codes", []) + b.get("reason_codes", []))
    run(t())


def test_in_process_client_turns_surprises_into_fail_closed():
    class Broken:
        def evaluate(self, req):
            raise RuntimeError("database gone")
    with pytest.raises(DecisionUnavailable):
        asyncio.run(InProcessDecisions(Broken()).evaluate({}))       # type: ignore[arg-type]


def test_the_dpop_tier_needs_a_live_proof_and_then_pays_within_a_standing_mandate(world):
    """A key-bound agent on Bill payer pays a named payee within its limits without asking; a bound token without a
    proof, or with another key's proof, is refused, and a stolen bound token sent as Bearer is refused too."""
    from valet.common.crypto import Key
    from valet.common.dpop import make_proof

    async def t():
        w = world
        bank = w.h.bank
        key, other = Key.generate(), Key.generate()
        now = int(time.time())
        token = w.idp.sign({"iss": w.idp.issuer, "aud": bank.cfg.issuer + "/mcp", "azp": "claude", "sub": "u-1",
                            "iat": now, "exp": now + 300, "valet_grant": w.grant["id"], "cnf": {"jkt": key.thumbprint}},
                           typ="at+jwt")
        url = bank.cfg.issuer + "/mcp"

        async def call(scheme: str, signer, method="tools/call", params=None):
            headers = {"Authorization": f"{scheme} {token}"}
            if signer is not None:
                headers["DPoP"] = make_proof(signer, "POST", url, access_token=token)
            return await w.h.browser.post("/mcp", headers=headers, json={
                "jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})

        assert (await call("Bearer", None, "tools/list")).status_code == 401        # stolen bound token as Bearer
        assert (await call("DPoP", None, "tools/list")).status_code == 401          # no proof
        assert (await call("DPoP", other, "tools/list")).status_code == 401         # another key's proof
        pay = {"name": "pay_existing_payee", "arguments": {"payee_id": "ben_water", "from_account_id": "acc_4821",
                                                           "amount": "100.00", "reason": "Water",
                                                           "idempotency_key": "dpop-water-01"}}
        r = (await call("DPoP", key, params=pay)).json()["result"]["structuredContent"]
        assert r["outcome"] == "APPROVED" and r["status"] == "paid" and r["receipt"]
        assert bank.store.one("SELECT balance FROM accounts WHERE id='acc_4821'")["balance"] == 18_430_55 - 100_00
        paid = [x for x in bank.receipts.for_grant(w.grant["id"]) if x["action"] == "payment"]
        assert paid and paid[0]["intent_evidence"] in ("standing_mandate", "agent_reported")
    run(t())
