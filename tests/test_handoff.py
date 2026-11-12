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


def test_idp_tokens_bind_the_grant_to_the_agents_key_and_idp_revoke_ends_it():
    async def t():
        idp = MockIdP(issuer="http://kc.test/realms/marula")
        h = harness(external_issuers={idp.issuer: ExternalIssuer(issuer=idp.issuer, audience="marula-api", jwks=idp.jwks)})
        gid = result_of((await decide(h, ticket())).text)["grant_id"]
        h.kaya.session.grant_id = gid
        h.kaya.session.access_token = idp.access_token(client_id="kaya", grant_id=gid, jkt=h.kaya.key.thumbprint, details=[])
        assert await h.kaya.accounts()
        assert h.bank.store.grant(gid)["jkt"] == h.kaya.key.thumbprint           # bound on first use
        # approvals still run through Valet (Keycloak's CIBA has no RAR): the bound key is what lets them work
        res = await h.kaya.pay("acc_4821", "City Power", "30087712", "100.00")
        await h.login()
        await h.decide(res["auth_req_id"])
        assert (await h.kaya.check_approval(res["auth_req_id"]))["outcome"] == "paid"
        # a token for the same grant bound to another key is refused
        from valet.common.crypto import Key
        other = Key.generate()
        h.kaya.session.access_token = idp.access_token(client_id="kaya", grant_id=gid, jkt=other.thumbprint, details=[])
        h.kaya.key = other
        with pytest.raises(ValetError) as ei:
            await h.kaya.accounts()
        assert ei.value.status == 401
        # the customer disconnects in the IdP's account pages; the IdP tells Valet
        r = await h.browser.delete(f"/internal/grants/{gid}", headers={"Authorization": "Bearer " + "i" * 32})
        assert r.json()["status"] == "revoked"
    run(t())


# ------------------------------------------------- Review: signing in again for an agent the customer already allows
async def connected(h: Harness, level: str = "bill_payer") -> dict:
    res = result_of((await decide(h, ticket(), level=level)).text)
    return h.bank.store.grant(res["grant_id"])


def live(h: Harness) -> list:
    return h.bank.store.q("SELECT id FROM grants WHERE client_id='kaya' AND status IN ('active','paused')")


def test_reconnecting_shows_the_review_screen_not_a_new_consent():
    async def t():
        h = harness()
        g = await connected(h)
        page = await h.browser.get("/handoff/consent", params={"ticket": ticket()})
        assert page.status_code == 200 and "Review Kaya" in page.text and "Keep as it is" in page.text
        assert 'name="level"' not in page.text                      # not the full consent form
        assert "Bill payer" in page.text and "last confirmed" in page.text and g["id"] not in page.text
    run(t())


def test_keep_returns_the_same_grant_and_records_the_confirmation():
    async def t():
        h = harness()
        g = await connected(h)
        h.bank.store.x("UPDATE grants SET confirmed_at=? WHERE id=?", g["created"] - 86400, g["id"])
        res = result_of((await h.browser.post("/handoff/decision", data={"ticket": ticket(), "decision": "keep"})).text)
        assert res["decision"] == "allow" and res["grant_id"] == g["id"]
        kept = h.bank.store.grant(g["id"])
        assert kept["status"] == "active" and kept["confirmed_at"] > g["created"] - 1
        assert kept["details"] == g["details"] and kept["consent_hash"] == g["consent_hash"]   # terms unchanged
        assert len(live(h)) == 1
        assert [r["action"] for r in h.bank.receipts.for_grant(g["id"])][:2] == ["reconfirm", "connect"]
    run(t())


def test_stop_revokes_and_the_agent_gets_access_denied():
    async def t():
        h = harness()
        g = await connected(h)
        res = result_of((await h.browser.post("/handoff/decision", data={"ticket": ticket(), "decision": "stop"})).text)
        assert res["decision"] == "deny" and "grant_id" not in res
        assert h.bank.store.grant(g["id"])["status"] == "revoked" and not live(h)
        # the next connect is a fresh consent, not a review
        page = await h.browser.get("/handoff/consent", params={"ticket": ticket()})
        assert 'name="level"' in page.text
    run(t())


def test_change_starts_from_todays_choice_and_replaces_the_old_grant():
    async def t():
        h = harness()
        old = await connected(h, level="view_only")
        tk = ticket(requested_level="bill_payer")
        page = await h.browser.get("/handoff/consent", params={"ticket": tk, "change": "1"})
        assert 'value="view_only" checked' in page.text             # what the customer allows today, not the ask
        res = result_of((await decide(h, tk, level="bill_payer")).text)
        assert res["grant_id"] != old["id"] and h.bank.store.grant(res["grant_id"])["level"] == "bill_payer"
        assert h.bank.store.grant(old["id"])["status"] == "revoked" and len(live(h)) == 1
    run(t())


def test_review_says_when_the_agent_asks_for_more_and_keep_does_not_give_it():
    async def t():
        h = harness()
        g = await connected(h, level="view_only")
        tk = ticket(requested_level="bill_payer")
        page = await h.browser.get("/handoff/consent", params={"ticket": tk})
        assert "asking for more: Bill payer" in page.text
        res = result_of((await h.browser.post("/handoff/decision", data={"ticket": tk, "decision": "keep"})).text)
        assert res["grant_id"] == g["id"] and h.bank.store.grant(g["id"])["level"] == "view_only"
    run(t())


def test_keeping_a_paused_agent_leaves_it_paused():
    async def t():
        h = harness()
        g = await connected(h)
        h.bank.store.set_status(g["id"], "paused")
        page = await h.browser.get("/handoff/consent", params={"ticket": ticket()})
        assert "Keeping leaves it paused" in page.text
        res = result_of((await h.browser.post("/handoff/decision", data={"ticket": ticket(), "decision": "keep"})).text)
        assert res["grant_id"] == g["id"] and h.bank.store.grant(g["id"])["status"] == "paused"
    run(t())


def test_keep_or_stop_without_a_live_grant_is_refused():
    async def t():
        h = harness()
        for choice in ("keep", "stop"):
            r = await h.browser.post("/handoff/decision", data={"ticket": ticket(), "decision": choice})
            assert r.status_code == 400 and "no connection" in r.text
        assert not h.bank.store.q("SELECT 1 FROM grants")
    run(t())


def test_a_database_from_before_review_gets_confirmed_at(tmp_path):
    import sqlite3

    from valet.bank.store import Store
    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE grants (id TEXT PRIMARY KEY, customer TEXT, client_id TEXT, level TEXT, details TEXT, "
                "status TEXT, created REAL, expires REAL, jkt TEXT, consent_hash TEXT, sub TEXT)")
    con.execute("INSERT INTO grants VALUES ('g1','cus_thandi','kaya','view_only','[]','active',100,9e9,NULL,'h','s')")
    con.commit()
    con.close()
    assert Store(str(db)).one("SELECT confirmed_at FROM grants WHERE id='g1'")["confirmed_at"] == 100
