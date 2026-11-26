"""
CIMD agents (valet/bank/cimd.py) and zero-integration Poppy sign-in (valet/bank/poppy.py).

An agent the bank has never registered connects with nothing but an HTTPS client_id serving its metadata, from a domain
the bank approves, and plain Poppy scopes. It reaches the same consent screen as any Valet agent, is capped at Approved
payer, and is stopped on its next call when the bank takes its domain off the approved list.
"""
from __future__ import annotations

import asyncio
import re
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from valet.agent.sdk import ValetError
from valet.bank.cimd import CimdInvalid, CimdResolver, approved, is_cimd_client_id, public_address
from valet.bank.registry import write_trust_file, DEFAULT_TRUST
from valet.common.crypto import Key
from valet.harness import BANK, Harness

AGENT = "https://agent.example/oauth/client.json"
CALLBACK = "https://agent.example/callback"
WATER = ("acc_4821", "Water & Sanitation", "40021187")


def run(coro):
    return asyncio.run(coro)


class Web:
    """The agent's website: serves its metadata document (and anything a test adds), and counts every fetch."""

    def __init__(self, key: Key, **overrides):
        self.key, self.calls = key, []
        self.docs = {AGENT: {"client_id": AGENT, "client_name": "Juno", "redirect_uris": [CALLBACK],
                             "token_endpoint_auth_method": "private_key_jwt",
                             "jwks": {"keys": [{**key.jwk, "kid": key.thumbprint}]}, **overrides}}
        self.raw: dict[str, httpx.Response] = {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.calls.append(url)
        if url in self.raw:
            return self.raw[url]
        if url in self.docs:
            return httpx.Response(200, json=self.docs[url])
        return httpx.Response(404)

    def resolver(self, domains=("agent.example",), cache_seconds: int = 300) -> CimdResolver:
        return CimdResolver(list(domains), cache_seconds, http=httpx.Client(transport=httpx.MockTransport(self.handler)),
                            check_address=lambda host: None)


def setup(domains=("agent.example",), trust: dict | None = None):
    key = Key.generate()
    web = Web(key)
    h = Harness(cimd=web.resolver(domains))
    if trust:
        write_trust_file(h.dir, {**DEFAULT_TRUST, **trust})
        h.bank.registry._loaded = 0
    return h, h.agent(AGENT, key, CALLBACK), web


async def consent_page(h: Harness, url: str) -> tuple[str, dict]:
    u = urlparse(url)
    page = await h.browser.get(u.path + "?" + u.query)
    assert page.status_code == 200, page.text
    q = parse_qs(u.query)
    return page.text, {"csrf": h.csrf(page.text), "client_id": q["client_id"][0], "request_uri": q["request_uri"][0],
                       "monthly": "200000", "account": "acc_4821", "decision": "allow"}


async def connect(h: Harness, agent, level: str, scope: str) -> str:
    url, pending = await agent.start_connect(scope=scope)
    _, form = await consent_page(h, url)
    r = await h.browser.post("/authorize/decision", data={**form, "level": level})
    assert r.status_code == 303, r.text
    back = parse_qs(urlparse(r.headers["location"]).query)
    await agent.finish_connect(back["code"][0], pending, back["state"][0], back["iss"][0])
    return agent.session.grant_id


# ------------------------------------------------------------------ discovery
def test_discovery_chain_a_poppy_agent_checks():
    async def t():
        h, _, _ = setup()
        async with httpx.AsyncClient(transport=h.transport, base_url=BANK) as c:
            poppy = (await c.get("/.well-known/poppy.json")).json()
            prm = (await c.get("/.well-known/oauth-protected-resource")).json()
            asm = (await c.get("/.well-known/oauth-authorization-server")).json()
            mcp = (await c.get("/.well-known/oauth-protected-resource/mcp")).json()
        # poppy.json names the issuer; the domain's resource metadata names the same server; the server lists the
        # domain back. Both sides point at each other (Poppy 1.0 section 3, RFC 9728, RFC 8414).
        assert prm["resource"] == BANK and prm["authorization_servers"] == [poppy["auth"]["issuer"]]
        assert asm["issuer"] == poppy["auth"]["issuer"] and BANK in asm["protected_resources"]
        assert prm["dpop_bound_access_tokens_required"] is True
        assert set(prm["scopes_supported"]) == set(poppy["auth"]["scopes"]) == set(asm["scopes_supported"])
        assert asm["client_id_metadata_document_supported"] is True
        assert mcp["resource"] == BANK + "/mcp"                     # MCP clients still get the MCP server's own document
        ext = poppy["extensions"]["veridact.net/valet"][0]
        assert ext["agent_identity"]["cimd"] == {"supported": True, "max_level": "approved_payer"}
        assert ext["agent_identity"]["veridact"]["max_level"] == "bill_payer"
        assert ext["scope_levels"]["payments:standing"] == "bill_payer"
        assert "veridactlabs/veridact-valet" in ext["spec"]
    run(t())


def test_without_cimd_configured_the_bank_says_so():
    async def t():
        h = Harness()
        async with httpx.AsyncClient(transport=h.transport, base_url=BANK) as c:
            asm = (await c.get("/.well-known/oauth-authorization-server")).json()
            poppy = (await c.get("/.well-known/poppy.json")).json()
        assert asm["client_id_metadata_document_supported"] is False
        assert poppy["extensions"]["veridact.net/valet"][0]["agent_identity"]["cimd"]["supported"] is False
    run(t())


# ------------------------------------------------------------------ a CIMD agent, end to end
def test_cimd_agent_signs_in_with_plain_poppy_scopes_and_is_capped_at_approved_payer():
    async def t():
        h, juno, _ = setup()
        await h.login()
        url, pending = await juno.start_connect(scope="payments:standing offline_access")
        page, form = await consent_page(h, url)
        assert "Identified by its website, agent.example. Not verified by Veridact." in page
        assert 'value="bill_payer"' not in page                      # not offered: above the CIMD tier's ceiling
        assert re.search(r'value="approved_payer"\s+checked', page)  # asked for Bill payer, preselected at the ceiling
        # A forged form can't get round it: the grant service refuses the level.
        r = await h.browser.post("/authorize/decision", data={**form, "level": "bill_payer"})
        assert r.status_code == 400
        assert h.bank.store.one("SELECT COUNT(*) n FROM grants")["n"] == 0

        gid = await connect(h, juno, "approved_payer", "payments:standing")
        assert juno.scope == "accounts:read payments:approve-each"   # what was granted, in Poppy's terms
        grant = h.bank.store.grant(gid)
        assert grant["client_id"] == AGENT and grant["level"] == "approved_payer"
        assert await juno.accounts()
        held = await juno.pay(*WATER, "100.00")
        assert held["outcome"] == "approval_pending" and held["reason_code"] == "approved_payer"
        rec = h.bank.registry.lookup(AGENT)
        assert (rec.tier, rec.operator, rec.name) == ("cimd", "agent.example", "Juno")
        screen = (await h.browser.get(f"/app/agents/{gid}")).text      # the customer's AI agents screen
        assert "Identified by its website · agent.example" in screen and "Not trusted" not in screen
    run(t())


def test_unknown_poppy_scope_is_refused():
    async def t():
        h, juno, _ = setup()
        with pytest.raises(ValetError) as e:
            await juno.start_connect(scope="payments:anything")
        assert e.value.error == "invalid_scope"
    run(t())


def test_taking_the_domain_off_the_approved_list_stops_live_grants_at_once():
    async def t():
        h, juno, _ = setup()
        await h.login()
        await connect(h, juno, "view_only", "accounts:read")
        assert await juno.accounts()
        h.bank.cimd.approved_domains.remove("agent.example")
        with pytest.raises(ValetError) as e:
            await juno.accounts()                                  # same token, no cache: refused on the next call
        assert e.value.status == 403 and e.value.error == "agent_untrusted"
        with pytest.raises(ValetError) as e:
            await juno.refresh()                                   # and it can't get new tokens
        assert e.value.error in ("invalid_client", "unauthorized_client")
        assert h.bank.registry.lookup(AGENT).name == "Juno"        # the bank's screens can still name it
    run(t())


def test_bank_denylists_a_cimd_operator_by_domain():
    async def t():
        h, juno, _ = setup()
        await h.login()
        await connect(h, juno, "view_only", "accounts:read")
        h.bank.deny("operator", "agent.example", "incident 42")
        with pytest.raises(ValetError) as e:
            await juno.accounts()
        assert e.value.error == "agent_denied"
    run(t())


def test_domain_not_approved_is_never_fetched():
    async def t():
        h, _, web = setup()
        stranger = h.agent("https://stranger.example/client.json", Key.generate(), "https://stranger.example/cb")
        with pytest.raises(ValetError) as e:
            await stranger.start_connect(scope="accounts:read")
        assert e.value.error == "invalid_client"
        assert web.calls == []                                     # the bank made no request on the stranger's behalf
    run(t())


# ------------------------------------------------------------------ Veridact on top of CIMD
def test_veridact_verified_cimd_agent_may_be_bill_payer_and_falls_back_when_withdrawn():
    async def t():
        trust = {AGENT: {"name": "Juno", "operator": "Juno Money (Pty) Ltd", "verified": True}}
        h, juno, _ = setup(trust=trust)
        await h.login()
        url, _ = await juno.start_connect(scope="payments:standing")
        page, _ = await consent_page(h, url)
        assert "Verified by Veridact" in page and "Runs from agent.example" in page and 'value="bill_payer"' in page
        await connect(h, juno, "bill_payer", "payments:standing")
        assert (await juno.pay(*WATER, "100.00"))["outcome"] == "paid"
        # Veridact withdraws the credential but the domain stays approved: the agent drops to the CIMD tier, and its
        # Bill payer grant now needs the customer's approval for every payment.
        write_trust_file(h.dir, {**DEFAULT_TRUST, AGENT: {**trust[AGENT], "verified": False}})
        h.bank.registry._loaded = 0
        held = await juno.pay(*WATER, "100.00")
        assert held["outcome"] == "approval_pending" and held["reason_code"] == "approved_payer"
        assert "identified only by its website" in held["reason"]
    run(t())


# ------------------------------------------------------------------ document checks
def test_client_id_url_rules():
    assert is_cimd_client_id(AGENT)
    for bad in ("http://agent.example/c", "https://agent.example", "https://agent.example/", "https://u:p@a.example/c",
                "https://agent.example/c#x", "https://agent.example/c?x=1", "https://agent.example/a/../c", "kaya"):
        assert not is_cimd_client_id(bad), bad


def test_approved_domain_patterns():
    assert approved("agent.example", ["agent.example"])
    assert approved("eu.agents.example", ["*.agents.example"])
    assert not approved("agents.example", ["*.agents.example"])
    assert not approved("evilagents.example", ["*.agents.example"])
    assert not approved("agent.example.evil", ["agent.example"])
    assert approved("anything.example", ["*"])


@pytest.mark.parametrize("overrides,raw", [
    ({"client_id": "https://agent.example/other.json"}, None),       # document claims another client
    ({"client_secret": "s3cret"}, None),                             # secrets have no place in public metadata
    ({"token_endpoint_auth_method": "client_secret_basic"}, None),
    ({"redirect_uris": ["http://agent.example/cb"]}, None),          # https only
    ({"jwks": {"keys": []}}, None),                                  # no key
    ({}, httpx.Response(302, headers={"Location": "https://elsewhere.example/doc"})),   # redirects refused
    ({}, httpx.Response(200, content=b"{" + b" " * 6000 + b"}")),   # too large
])
def test_bad_documents_are_refused(overrides, raw):
    web = Web(Key.generate(), **overrides)
    if raw is not None:
        web.raw[AGENT] = raw
    r = web.resolver()
    assert r.resolve(AGENT) is None and r.last_error


def test_keys_from_jwks_uri_must_be_on_the_same_host():
    key = Key.generate()
    web = Web(key)
    del web.docs[AGENT]["jwks"]
    web.docs[AGENT]["jwks_uri"] = "https://keys.elsewhere.example/jwks"
    assert web.resolver().resolve(AGENT) is None
    web.docs[AGENT]["jwks_uri"] = "https://agent.example/jwks"
    web.docs["https://agent.example/jwks"] = {"keys": [key.jwk]}
    meta, keys = web.resolver().resolve(AGENT)
    assert keys == [key.jwk]


def test_private_addresses_are_refused():
    for host in ("localhost", "127.0.0.1", "10.0.0.8", "169.254.169.254", "[::1]".strip("[]")):
        with pytest.raises(CimdInvalid):
            public_address(host)


def test_documents_are_cached_and_the_last_good_copy_survives_one_outage():
    web = Web(Key.generate())
    r = web.resolver(cache_seconds=60)
    assert r.resolve(AGENT) and r.resolve(AGENT)
    assert len(web.calls) == 1
    r._docs[AGENT].at -= 61                                          # stale: refetch, and the site is down
    web.raw[AGENT] = httpx.Response(503)
    assert r.resolve(AGENT)                                          # one more period on the last good copy
    r._docs[AGENT].at -= 61
    assert r.resolve(AGENT) is None
