"""
Lane A: Veridact known-assistant entries. The bank checks the attester's SD-JWT VC entry and Token Status List itself;
a suspended or withdrawn entry stops the assistant on its next call, and the entry's ceiling is never exceeded.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
import zlib

import httpx

from valet.bank.known_assistants import VCT, KnownAssistants
from valet.common.crypto import Key

from test_mcp import World, run

ISSUER = "https://veridact.test"
LIST = ISSUER + "/status/known-assistants/1"


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class FakeAttester:
    """Just enough of veridact-attester: issuer metadata, one entry, a 2-bit status list."""

    def __init__(self):
        self.key, self.kid = Key.generate(), "ka-1"
        self.status, self.up, self.idx = 0, True, 4711
        self.tamper: str | None = None
        self.claims = {"sub": "claude", "name": "Claude", "operator": {"name": "Anthropic PBC"},
                       "max_level": "approved_payer"}

    def entry(self) -> str:
        now = int(time.time())
        d = b64e(json.dumps(["salt", "jurisdiction_note", "US (Delaware)"]).encode())
        claims = {"iss": ISSUER, "vct": VCT, "iat": now, "exp": now + 3600, **self.claims,
                  "status": {"status_list": {"idx": self.idx, "uri": LIST}},
                  "_sd": [b64e(hashlib.sha256(d.encode()).digest())], "_sd_alg": "sha-256"}
        if self.tamper == "vct":
            claims["vct"] = "https://example.test/other"
        signer = Key.generate() if self.tamper == "key" else self.key
        jwt = signer.sign(claims, headers={"typ": "dc+sd-jwt", "kid": self.kid})
        if self.tamper == "disclosure":
            d = b64e(json.dumps(["salt", "max_level", "bill_payer"]).encode())
        return f"{jwt}~{d}~"

    def status_list(self) -> str:
        raw = bytearray(131_072 // 4)
        byte, shift = divmod(self.idx * 2, 8)
        raw[byte] |= self.status << shift
        now = int(time.time())
        return self.key.sign({"iss": ISSUER, "sub": LIST, "iat": now, "exp": now + 600, "ttl": 10,
                              "status_list": {"bits": 2, "lst": b64e(zlib.compress(bytes(raw)))}},
                             headers={"typ": "statuslist+jwt", "kid": self.kid})

    def handler(self, request: httpx.Request) -> httpx.Response:
        if not self.up:
            raise httpx.ConnectError("attester down")
        path = request.url.path
        if path == "/.well-known/jwt-vc-issuer":
            return httpx.Response(200, json={"issuer": ISSUER, "jwks": {"keys": [{**self.key.jwk, "kid": self.kid}]}})
        if path == "/known-assistants/claude":
            return httpx.Response(200, text=self.entry())
        if path == "/status/known-assistants/1":
            return httpx.Response(200, text=self.status_list())
        return httpx.Response(404)


def setup(level: str = "bill_payer") -> tuple[World, FakeAttester]:
    w, att = World(level=level), FakeAttester()
    w.h.bank.known_assistants = KnownAssistants(ISSUER, {"claude": "claude"}, fetch="http://veridact:8100",
                                                cache_seconds=0,
                                                http=httpx.Client(transport=httpx.MockTransport(att.handler)))
    return w, att


def test_a_valid_entry_admits_claude_with_its_verified_operator_name():
    w, att = setup()
    known = w.h.bank.known_assistants
    v = known.check("claude")
    assert v["status"] == "valid" and v["operator"] == "Anthropic PBC" and v["max_level"] == "approved_payer"
    assert known.display_name("claude") == "Claude, operated by Anthropic PBC"
    assert not known.covers("kaya")

    async def t():
        assert (await w.tool("list_accounts"))["accounts"]
        rec = w.h.bank.receipts.for_grant(w.grant["id"])[0]
        assert rec["veridact"]["status"] == "valid" and rec["veridact"]["operator"] == "Anthropic PBC"
        held = await w.tool("pay_existing_payee", payee_id="ben_water", from_account_id="acc_4821", amount="640.00",
                            reason="Water bill", idempotency_key="water-0001")
        assert held["outcome"] == "APPROVAL_REQUIRED"
        await w.h.login()
        page = await w.h.decide(held["payment_ref"], approve=True)
        assert "Claude, operated by Anthropic PBC says: Water bill" in page
    run(t())


def test_suspending_the_entry_stops_claude_on_its_next_call_and_restoring_brings_it_back():
    async def t():
        w, att = setup()
        assert (await w.tool("list_accounts"))["accounts"]
        att.status = 2                                                  # Veridact suspends Claude
        assert (await w.tool("list_accounts"))["reason_codes"] == ["ASSISTANT_SUSPENDED"]
        assert (await w.rpc("tools/list")).json()["result"]["tools"] == []
        paid = await w.tool("pay_existing_payee", payee_id="ben_water", from_account_id="acc_4821", amount="1.00",
                            reason="x", idempotency_key="k-00000001")
        assert paid["reason_codes"] == ["ASSISTANT_SUSPENDED"]
        att.status = 0
        assert (await w.tool("list_accounts"))["accounts"]
        assert (await w.tool("pay_existing_payee", payee_id="ben_water", from_account_id="acc_4821", amount="1.00",
                             reason="x", idempotency_key="k-00000001"))["outcome"] == "APPROVAL_REQUIRED"
        att.status = 1                                                  # withdrawn for good
        assert (await w.tool("list_accounts"))["reason_codes"] == ["ASSISTANT_WITHDRAWN"]
        codes = [r.get("reason_codes") for r in w.h.bank.receipts.for_grant(w.grant["id"])]
        assert ["ASSISTANT_SUSPENDED"] in codes and ["ASSISTANT_WITHDRAWN"] in codes
    run(t())


def test_if_veridact_cannot_be_checked_reads_continue_and_payments_fail_closed():
    async def t():
        w, att = setup()
        att.up = False
        assert w.h.bank.known_assistants.check("claude")["status"] == "unavailable"
        assert (await w.tool("list_accounts"))["accounts"]
        paid = await w.tool("pay_existing_payee", payee_id="ben_water", from_account_id="acc_4821", amount="1.00",
                            reason="x", idempotency_key="k-00000001")
        assert paid["reason_codes"] == ["ASSISTANT_NOT_VERIFIED"]
    run(t())


def test_an_entry_that_does_not_verify_is_no_entry():
    for tamper in ("key", "vct", "disclosure"):
        w, att = setup()
        att.tamper = tamper
        assert w.h.bank.known_assistants.check("claude")["status"] == "unavailable", tamper


def test_a_disclosure_is_applied_once_its_digest_matches():
    w, att = setup()
    claims = w.h.bank.known_assistants._entry("claude")
    assert claims["jurisdiction_note"] == "US (Delaware)" and "_sd" not in claims


def test_the_entrys_ceiling_holds_even_for_a_key_bound_client():
    """A DPoP-bound client on a Bill payer mandate pays within its limits without asking, unless Veridact's ceiling
    for the assistant is Approved payer: then the customer approves every payment."""
    w, att = setup()
    svc = w.h.bank.decision_service

    def pay(key: str, veridact: dict | None) -> dict:
        ctx = {"agent": "claude", "valet_grant": w.grant["id"], "token_tier": "dpop", "channel": "mcp",
               "payment": {"payee": "ben_water", "amount": "100.00"}, "idempotency_key": key, "agent_reason": "x"}
        if veridact is not None:
            ctx["veridact"] = veridact
        return svc.evaluate({"subject": {"type": "identity", "id": "u-1"}, "action": {"name": "pay_existing_payee"},
                             "resource": {"type": "account", "id": "acc_4821"}, "context": ctx})

    capped = pay("dpop-0000001", w.h.bank.assistant("claude"))
    assert capped["decision"] is False and capped["context"]["reason"] == "assistant_ceiling"
    att.claims["max_level"] = "bill_payer"
    free = pay("dpop-0000002", w.h.bank.assistant("claude"))
    assert free["decision"] is True and free["context"]["valet"]["outcome"] == "reserved"
    missing = pay("dpop-0000003", None)                         # the server forgot to check Veridact
    assert missing["decision"] is False and missing["context"]["reason"] == "assistant_not_verified"


def test_the_consent_screen_names_the_verified_operator_and_a_suspended_assistant_cannot_connect():
    from test_handoff import decide, harness, ticket

    async def t():
        h, att = harness(), FakeAttester()
        h.bank.known_assistants = KnownAssistants(ISSUER, {"claude": "claude"}, cache_seconds=0,
                                                  http=httpx.Client(transport=httpx.MockTransport(att.handler)))
        page = await h.browser.get("/handoff/consent", params={"ticket": ticket(client_id="claude")})
        assert page.status_code == 200 and "operated by Anthropic PBC" in page.text and "Known assistant" in page.text and "not for this particular session" in page.text and "Verified by Veridact" not in page.text
        att.status = 2
        refused = await h.browser.get("/handoff/consent", params={"ticket": ticket(client_id="claude")})
        assert "Veridact has suspended Claude" in refused.text
        late = await decide(h, ticket(client_id="claude"), level="approved_payer")
        assert "Veridact has suspended Claude" in late.text
        assert not h.bank.store.q("SELECT 1 FROM grants WHERE client_id='claude'")
    run(t())
