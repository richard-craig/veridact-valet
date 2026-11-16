"""
Consent hand-off with the bank's IdP (native mode), as the Keycloak extension in extensions/keycloak-valet does it:
the IdP signs a ticket and sends the customer to Valet; Valet shows the consent screen, registers the grant and
posts a signed result back to the IdP's login. Tickets here are built exactly as the extension builds them.
"""
from __future__ import annotations

import asyncio
import re
import time

import jwt
import pytest

from valet.agent.sdk import ValetError
from valet.bank import levels as L
from valet.bank.tokens import ExternalIssuer
from valet.harness import BANK, Harness
from valet.testing.mock_idp import MockIdP

SECRET = "handoff-secret-at-least-32-characters!"
IDP = "keycloak:marula"
RETURN = "http://kc.test/realms/marula/login-actions/authenticate?session_code=abc&execution=x"


def run(coro):
    return asyncio.run(coro)


def harness(**kw) -> Harness:
    return Harness(handoff_secret=SECRET, handoff_idps={IDP: "http://kc.test/realms/marula/"}, internal_secret="i" * 32, **kw)


def ticket(**over) -> str:
    now = int(time.time())
    claims = {"iss": IDP, "aud": BANK, "iat": now, "exp": now + 300, "nonce": "n-" + str(time.time_ns()),
              "customer": "thandi", "email": "thandi@example.com", "client_id": "kaya", "requested_level": "bill_payer",
              "return_to": RETURN, **over}
    return jwt.encode(claims, over.pop("_secret", SECRET) if "_secret" in over else SECRET, algorithm="HS256")


async def decide(h: Harness, t: str, decision: str = "allow", level: str = "bill_payer", monthly: int = 1_000_00):
    return await h.browser.post("/handoff/decision", data={"ticket": t, "decision": decision, "level": level,
                                                           "monthly": str(monthly), "account": "acc_4821"})


def result_of(html: str) -> dict:
    token = re.search(r'name="valet_result" value="([^"]+)"', html).group(1)
    assert re.search(r'action="([^"]+)"', html).group(1).replace("&amp;", "&") == RETURN
    return jwt.decode(token, SECRET, algorithms=["HS256"], audience=IDP)


def test_consent_screen_shows_the_verified_agent_and_requested_level():
    async def t():
        h = harness()
        page = await h.browser.get("/handoff/consent", params={"ticket": ticket()})
        assert page.status_code == 200 and "Verified by Veridact" in page.text and "Kaya Labs" in page.text
        assert 'value="bill_payer" checked' in page.text and 'action="/handoff/decision"' in page.text
    run(t())


def test_allow_registers_the_grant_and_returns_a_signed_result_to_the_idp():
    async def t():
        h = harness()
        tk = ticket()
        r = await decide(h, tk, level="bill_payer", monthly=1_000_00)
        res = result_of(r.text)
        assert res["decision"] == "allow" and res["iss"] == BANK
        assert res["nonce"] == jwt.decode(tk, SECRET, algorithms=["HS256"], audience=BANK)["nonce"]
        g = h.bank.store.grant(res["grant_id"])
        assert g["status"] == "active" and g["level"] == "bill_payer" and g["customer"] == "cus_thandi"
        assert L.monthly_limit(g["details"]) == 1_000_00
    run(t())


def test_customer_can_choose_less_than_the_agent_asked_for():
    async def t():
        h = harness()
        res = result_of((await decide(h, ticket(requested_level="bill_payer"), level="view_only")).text)
        assert h.bank.store.grant(res["grant_id"])["level"] == "view_only"
    run(t())


def test_deny_creates_nothing():
    async def t():
        h = harness()
        res = result_of((await decide(h, ticket(), decision="deny")).text)
        assert res["decision"] == "deny" and "grant_id" not in res
        assert not h.bank.store.q("SELECT 1 FROM grants")
    run(t())


@pytest.mark.parametrize("bad", ["secret", "audience", "expired", "idp", "return_to", "agent", "customer"])
def test_bad_tickets_are_refused(bad):
    async def t():
        h = harness()
        over = {"secret": {"_secret": "x" * 40}, "audience": {"aud": "http://elsewhere"}, "expired": {"exp": 1},
                "idp": {"iss": "keycloak:evil"}, "return_to": {"return_to": "http://evil.test/steal"},
                "agent": {"client_id": "copycat"}, "customer": {"customer": "mallory", "email": "m@x"}}[bad]
        r = await h.browser.get("/handoff/consent", params={"ticket": ticket(**over)})
        assert r.status_code == 400
        assert (await decide(h, ticket(**over))).status_code == 400
        assert not h.bank.store.q("SELECT 1 FROM grants")
    run(t())


def test_a_ticket_answers_once():
    async def t():
        h = harness()
        tk = ticket()
        assert (await decide(h, tk)).status_code == 200
        assert (await decide(h, tk)).status_code == 400
        assert len(h.bank.store.q("SELECT 1 FROM grants")) == 1
    run(t())


def test_handoff_is_off_without_a_secret():
    async def t():
        h = Harness()
        assert (await h.browser.get("/handoff/consent", params={"ticket": ticket()})).status_code == 400
    run(t())


def native(issuer: str = "http://kc.test/realms/marula", **kw) -> tuple[Harness, MockIdP]:
    idp = MockIdP(issuer=issuer)
    ext = {idp.issuer: ExternalIssuer(issuer=idp.issuer, audience="marula-api", jwks=idp.jwks)}
    return harness(external_issuers=ext, **kw), idp


def use(h: Harness, idp: MockIdP, gid: str, key=None) -> None:
    key = key or h.kaya.key
    h.kaya.key, h.kaya.session.grant_id = key, gid
    h.kaya.session.access_token = idp.access_token(client_id="kaya", grant_id=gid, jkt=key.thumbprint, details=[])


def test_the_grant_is_bound_to_the_agents_key_at_consent_and_idp_revoke_ends_it():
    async def t():
        from valet.common.crypto import Key
        h, idp = native()
        # the IdP learned the agent's key during authorisation (dpop_jkt) and passes it in the ticket
        gid = result_of((await decide(h, ticket(dpop_jkt=h.kaya.key.thumbprint))).text)["grant_id"]
        assert h.bank.store.grant(gid)["jkt"] == h.kaya.key.thumbprint           # bound before any token or API call
        # a valid IdP token for the same grant and agent, but bound to another key, cannot claim the grant
        mine = h.kaya.key
        use(h, idp, gid, Key.generate())
        with pytest.raises(ValetError) as ei:
            await h.kaya.accounts()
        assert ei.value.status == 401
        use(h, idp, gid, mine)
        assert await h.kaya.accounts()
        # approvals still run through Valet (Keycloak's CIBA has no RAR): the bound key is what lets them work
        res = await h.kaya.pay("acc_4821", "City Power", "30087712", "100.00")
        await h.login()
        await h.decide(res["auth_req_id"])
        assert (await h.kaya.check_approval(res["auth_req_id"]))["outcome"] == "paid"
        # the customer disconnects in the IdP's account pages; the IdP tells Valet
        r = await h.browser.delete(f"/internal/grants/{gid}", headers={"Authorization": "Bearer " + "i" * 32})
        assert r.json()["status"] == "revoked"
    run(t())


def test_a_grant_with_no_key_is_refused_unless_the_bank_allows_binding_at_first_use():
    async def t():
        from valet.common.crypto import Key
        h, idp = native()
        gid = result_of((await decide(h, ticket())).text)["grant_id"]            # an IdP that did not pass dpop_jkt
        assert h.bank.store.grant(gid)["jkt"] is None
        use(h, idp, gid)
        with pytest.raises(ValetError) as ei:
            await h.kaya.accounts()
        assert ei.value.status == 401 and "not bound" in str(ei.value)
        assert h.bank.store.grant(gid)["jkt"] is None                            # and the call did not bind it

        # the bank turns on first-use binding for an IdP that cannot pass the key: weaker, and recorded as such
        # only for a demo: the fictional payments adapter and an identity platform on this machine
        h, idp = native("http://127.0.0.1:8080/realms/marula", allow_first_use_binding=True)
        assert h.bank.key_binding == "first_use_demo_only"
        assert (await h.browser.get("/readyz")).json()["key_binding"] == "first_use_demo_only"
        gid = result_of((await decide(h, ticket())).text)["grant_id"]
        use(h, idp, gid)
        assert await h.kaya.accounts()
        assert h.bank.store.grant(gid)["jkt"] == h.kaya.key.thumbprint
        assert any(r["action"] == "key_binding" and r["basis"] == "first_use" for r in h.bank.receipts.for_grant(gid))
        use(h, idp, gid, Key.generate())
        with pytest.raises(ValetError) as ei:
            await h.kaya.accounts()
        assert ei.value.status == 401
    run(t())


def test_first_use_binding_refuses_to_start_outside_a_demo():
    with pytest.raises(RuntimeError, match="demo"):
        native(allow_first_use_binding=True)                                    # a remote identity platform
    h, _ = native()
    assert h.bank.key_binding == "at_consent"


def test_a_native_grant_only_accepts_tokens_from_the_issuer_it_was_made_with():
    async def t():
        a, b = MockIdP(issuer="http://kc.test/realms/marula"), MockIdP(issuer="http://kc.test/realms/other")
        ext = {i.issuer: ExternalIssuer(issuer=i.issuer, audience="marula-api", jwks=i.jwks) for i in (a, b)}
        h = harness(external_issuers=ext)
        gid = result_of((await decide(h, ticket(token_issuer=a.issuer, dpop_jkt=h.kaya.key.thumbprint))).text)["grant_id"]
        assert h.bank.store.grant(gid)["issuer"] == a.issuer
        use(h, a, gid)
        assert await h.kaya.accounts()
        use(h, b, gid)                                                           # same grant id, another platform
        with pytest.raises(ValetError) as ei:
            await h.kaya.accounts()
        assert ei.value.status == 401 and "different issuer" in str(ei.value)
    run(t())
