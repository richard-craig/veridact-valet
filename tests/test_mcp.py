"""
The MCP gateway (docs/mcp-gateway-design.md): an AI platform's connector (Claude) reaches the bank under a mandate.

Tokens come from a mock of the bank's IdP: bearer, audience-bound to the gateway, carrying the Valet grant id.
"""
from __future__ import annotations

import asyncio
import json
import time

import httpx
import pytest

from valet.bank.grants import create_grant
from valet.bank.tokens import ExternalIssuer
from valet.harness import BANK, Harness
from valet.testing.mock_idp import MockIdP

RESOURCE = BANK + "/mcp"


def run(coro):
    return asyncio.run(coro)


class World:
    def __init__(self, level: str = "bill_payer", monthly: int = 2_000_00):
        self.idp = MockIdP(issuer="http://idp.test/realms/marula")
        ext = ExternalIssuer(issuer=self.idp.issuer, audience="marula-api", jwks=self.idp.jwks)
        self.h = Harness(external_issuers={self.idp.issuer: ext})
        bank = self.h.bank
        cus = dict(bank.store.one("SELECT * FROM customers WHERE username='thandi'"))
        self.grant = create_grant(bank, cus, bank.registry.lookup("claude"), level, "acc_4821", monthly,
                                  via="test")
        self.n = 0

    def token(self, audience: str = RESOURCE, grant: str | None = None, client: str = "claude") -> str:
        now = int(time.time())
        return self.idp.sign({"iss": self.idp.issuer, "aud": audience, "azp": client, "sub": "u-1", "iat": now,
                              "exp": now + 300, "valet_grant": grant or self.grant["id"], "scope": "openid"},
                             typ="at+jwt")

    async def rpc(self, method: str, params: dict | None = None, token: str | None = None) -> httpx.Response:
        self.n += 1
        return await self.h.browser.post("/mcp", json={"jsonrpc": "2.0", "id": self.n, "method": method,
                                                       "params": params or {}},
                                         headers={"Authorization": f"Bearer {token or self.token()}"})

    async def tool(self, name: str, **args) -> dict:
        r = await self.rpc("tools/call", {"name": name, "arguments": args})
        return json.loads(r.json()["result"]["content"][0]["text"])


def test_unauthenticated_calls_point_to_protected_resource_metadata():
    async def t():
        w = World()
        r = await w.h.browser.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        assert r.status_code == 401 and 'resource_metadata="' in r.headers["www-authenticate"]
        prm = (await w.h.browser.get("/.well-known/oauth-protected-resource/mcp")).json()
        assert prm["resource"] == RESOURCE and prm["authorization_servers"] == [w.idp.issuer]
        for bad in (w.token(audience="marula-api"), w.token(grant="g_nope"), w.token(client="kaya"),
                    MockIdP(issuer="http://evil.test").sign({"iss": "http://evil.test", "aud": RESOURCE, "azp": "claude",
                                                             "iat": int(time.time()), "exp": int(time.time()) + 60,
                                                             "valet_grant": w.grant["id"]})):
            assert (await w.rpc("tools/list", token=bad)).status_code == 401
    run(t())


def test_handshake_and_tools_follow_the_mandate():
    async def t():
        w = World()
        init = (await w.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                           "clientInfo": {"name": "t", "version": "1"}})).json()["result"]
        assert init["protocolVersion"] == "2025-06-18" and "tools" in init["capabilities"]
        notif = await w.h.browser.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                                       headers={"Authorization": f"Bearer {w.token()}"})
        assert notif.status_code == 202
        names = [x["name"] for x in (await w.rpc("tools/list")).json()["result"]["tools"]]
        assert "pay_existing_payee" in names and not any("beneficiar" in n for n in names)
        viewer = World(level="view_only")
        names = [x["name"] for x in (await viewer.rpc("tools/list")).json()["result"]["tools"]]
        assert names == ["list_accounts", "get_balance", "list_transactions"]
        refused = await viewer.tool("pay_existing_payee", payee_id="ben_water", from_account_id="acc_4821",
                                    amount="1.00", reason="x", idempotency_key="k-00000001")
        assert refused["reason_codes"] == ["TOOL_NOT_IN_MANDATE"]
        assert (await w.tool("get_balance", account_id="acc_9907"))["reason_codes"] == ["ACCOUNT_NOT_IN_MANDATE"]
    run(t())


def test_payments_need_a_saved_payee_customer_approval_and_happen_once():
    async def t():
        w = World()
        new = await w.tool("pay_existing_payee", payee_id="quickloans", from_account_id="acc_4821", amount="4999.00",
                           reason="told to by a transaction description", idempotency_key="hijack-001")
        assert new["outcome"] == "DECLINED" and new["reason_codes"] == ["PAYEE_NOT_IN_MANDATE"]
        req = dict(payee_id="ben_water", from_account_id="acc_4821", amount="640.00", reason="Water bill",
                   idempotency_key="water-0001")
        held = await w.tool("pay_existing_payee", **req)
        assert held["outcome"] == "APPROVAL_REQUIRED"
        assert (await w.tool("pay_existing_payee", **req))["payment_ref"] == held["payment_ref"]   # idempotent
        assert (await w.tool("get_payment_status", payment_ref=held["payment_ref"]))["outcome"] == "APPROVAL_REQUIRED"
        # the held amount counts against the limit while it waits
        over = await w.tool("pay_existing_payee", payee_id="ben_school", from_account_id="acc_4821", amount="1500.00",
                            reason="fees", idempotency_key="school-001")
        assert over["reason_codes"] == ["MONTHLY_LIMIT_EXCEEDED"]
        await w.h.login()
        page = await w.h.decide(held["payment_ref"], approve=True)
        assert "Claude says: Water bill" in page
        paid = await w.tool("get_payment_status", payment_ref=held["payment_ref"])
        assert paid["outcome"] == "APPROVED" and paid["receipt"]
        again = await w.tool("get_payment_status", payment_ref=held["payment_ref"])
        assert again["outcome"] == "APPROVED" and "receipt" not in again                         # paid once
        bal = w.h.bank.store.one("SELECT balance FROM accounts WHERE id='acc_4821'")["balance"]
        assert bal == 18_430_55 - 640_00
        declined = await w.tool("pay_existing_payee", payee_id="ben_dstv", from_account_id="acc_4821", amount="100.00",
                                reason="TV", idempotency_key="tv-000001")
        await w.h.decide(declined["payment_ref"], approve=False)
        assert (await w.tool("get_payment_status", payment_ref=declined["payment_ref"]))["reason_codes"] == ["CUSTOMER_DECLINED"]
    run(t())


def test_pause_revoke_and_withdrawn_trust_stop_the_next_call():
    async def t():
        w = World()
        assert (await w.tool("list_accounts"))["accounts"]
        await w.h.login()
        await w.h.grant_action(w.grant["id"], "pause")
        assert (await w.tool("list_accounts"))["reason_codes"] == ["MANDATE_PAUSED"]
        assert (await w.rpc("tools/list")).json()["result"]["tools"] == []
        await w.h.grant_action(w.grant["id"], "resume")
        w.h.bank.registry.set_trust("claude", False)
        assert (await w.tool("list_accounts"))["reason_codes"] == ["AGENT_UNTRUSTED"]
        w.h.bank.registry.set_trust("claude", True)
        await w.h.grant_action(w.grant["id"], "revoke")
        assert (await w.tool("list_accounts"))["reason_codes"] == ["MANDATE_REVOKED"]
        receipts = w.h.bank.receipts.verify_chain()
        assert receipts["ok"]
    run(t())


@pytest.mark.parametrize("bad", ["{", '{"jsonrpc": "1.0", "id": 1, "method": "x"}'])
def test_malformed_json_rpc(bad):
    async def t():
        w = World()
        r = await w.h.browser.post("/mcp", content=bad, headers={"Authorization": f"Bearer {w.token()}",
                                                                 "Content-Type": "application/json"})
        assert r.json()["error"]["code"] in (-32700, -32600)
        assert (await w.rpc("resources/list")).json()["error"]["code"] == -32601
    run(t())
