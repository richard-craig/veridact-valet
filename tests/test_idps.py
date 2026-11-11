"""
Valet with the bank's own identity provider.

Federated mode: customers sign in through any OpenID Connect provider (here a mock signing RS256, as Auth0,
Keycloak, Entra ID and Okta do by default). Native mode: the bank's own authorisation server issues the agent's
tokens and registers consents with Valet's grant service. In both, Valet's enforcement is unchanged.
"""
from __future__ import annotations

import asyncio
import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from valet.agent.sdk import ValetError
from valet.bank import levels as L
from valet.bank.idp import OidcConfig, OidcSignIn
from valet.bank.tokens import ExternalIssuer
from valet.bank.web import COOKIE, _ser
from valet.harness import BANK, Harness
from valet.testing.mock_idp import MockIdP

SECRET = "internal-test-secret"
WATER = ("acc_4821", "Water & Sanitation", "40021187")
POWER = ("acc_4821", "City Power", "30087712")


def run(coro):
    return asyncio.run(coro)


def oidc_harness(idp: MockIdP, claim: str = "preferred_username") -> Harness:
    cfg = OidcConfig(issuer=idp.issuer, client_id=idp.client_id, client_secret=idp.client_secret,
                     customer_claim=claim, redirect_uri=BANK + "/login/callback")
    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=idp.app), base_url=idp.issuer)
    return Harness(signin=OidcSignIn(cfg, http=http))


async def oidc_login(h: Harness, idp: MockIdP, next_url: str = "/app", step_up: bool = False) -> httpx.Response:
    """The customer's browser: bank -> IdP -> bank callback. Returns the bank's final response."""
    r = await h.browser.get("/login", params={"next": next_url, **({"step_up": "1"} if step_up else {})})
    assert r.status_code == 303 and r.headers["location"].startswith(idp.issuer + "/authorize")
    to_idp = urlparse(r.headers["location"])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=idp.app), base_url=idp.issuer) as browser_at_idp:
        back = await browser_at_idp.get(to_idp.path + "?" + to_idp.query)
    assert back.status_code == 303
    cb = urlparse(back.headers["location"])
    return await h.browser.get(cb.path + "?" + cb.query)


# ------------------------------------------------------------ federated mode
def test_customer_signs_in_with_the_banks_oidc_provider():
    async def t():
        idp = MockIdP()
        h = oidc_harness(idp)
        r = await oidc_login(h, idp)
        assert r.status_code == 303 and r.headers["location"] == "/app"
        assert (await h.browser.get("/app")).status_code == 200      # signed in: no redirect to /login
        q = idp.last_authorize
        assert q["code_challenge_method"] == "S256" and q["nonce"] and q["scope"].startswith("openid")
        # the demo password form is switched off when the bank's IdP owns sign-in
        r = await h.browser.post("/login", data={"username": "thandi", "password": "demo"})
        assert r.headers["location"] == "/login"
    run(t())


def test_email_claim_mapping_suits_auth0_and_entra():
    async def t():
        idp = MockIdP(user={"sub": "auth0|abc", "email": "thandi@example.com"})
        h = oidc_harness(idp, claim="email")
        assert (await oidc_login(h, idp)).status_code == 303
    run(t())


def test_full_connect_flow_works_with_oidc_sign_in():
    async def t():
        idp = MockIdP()
        h = oidc_harness(idp)
        url, pending = await h.kaya.start_connect("bill_payer")
        u = urlparse(url)
        r = await h.browser.get(u.path + "?" + u.query)              # not signed in yet: sent to sign in
        nxt = parse_qs(urlparse(r.headers["location"]).query)["next"][0]
        assert (await oidc_login(h, idp, nxt)).headers["location"] == nxt
        _, back = await h.consent(url)
        await h.kaya.finish_connect(back["code"][0], pending, back["state"][0])
        assert (await h.kaya.pay(*WATER, "640.00"))["outcome"] == "paid"
    run(t())


@pytest.mark.parametrize("problem", ["unknown_user", "aud", "nonce", "state"])
def test_bad_sign_ins_are_refused(problem):
    async def t():
        idp = MockIdP(user={"sub": "x", "preferred_username": "mallory"} if problem == "unknown_user" else
                      {"sub": "u-123", "preferred_username": "thandi"}, tamper=problem if problem in ("aud", "nonce") else "")
        h = oidc_harness(idp)
        if problem == "state":
            await h.browser.get("/login")
            r = await h.browser.get("/login/callback", params={"code": "x", "state": "forged"})
        else:
            r = await oidc_login(h, idp)
        assert r.status_code == 403
        assert COOKIE not in h.browser.cookies
    run(t())


def test_consent_and_approval_need_a_recent_sign_in():
    async def t():
        idp = MockIdP()
        h = oidc_harness(idp)
        await oidc_login(h, idp)
        # make the session look 10 minutes old (the bank's step-up window is 5)
        stale = _ser(h.bank).dumps({"cid": "cus_thandi", "at": int(time.time()) - 600, "via": "oidc"})
        h.browser.cookies.set(COOKIE, stale, domain="bank.test")
        url, _ = await h.kaya.start_connect()
        u = urlparse(url)
        r = await h.browser.get(u.path + "?" + u.query)
        assert r.status_code == 303 and "step_up=1" in r.headers["location"]
        r = await h.browser.get(r.headers["location"])
        q = parse_qs(urlparse(r.headers["location"]).query)
        assert q["max_age"] == ["0"] and q["prompt"] == ["login"]     # the IdP is asked for a fresh sign-in
        # an IdP that ignores max_age (old auth_time) is not trusted for step-up
        idp.auth_age = 3600
        assert (await oidc_login(h, idp, "/app", step_up=True)).status_code == 403
        idp.auth_age = 0
        assert (await oidc_login(h, idp, "/app", step_up=True)).status_code == 303
    run(t())


def test_local_demo_sign_in_also_steps_up():
    async def t():
        h = Harness()
        gid = await h.connect()
        res = await h.kaya.pay(*POWER, "100.00")
        stale = _ser(h.bank).dumps({"cid": "cus_thandi", "at": int(time.time()) - 600, "via": "local"})
        h.browser.cookies.set(COOKIE, stale, domain="bank.test")
        r = await h.browser.get(f"/app/approvals/{res['auth_req_id']}")
        assert r.status_code == 303 and "step_up=1" in r.headers["location"]
        assert "Confirm it" in (await h.browser.get(r.headers["location"])).text
        assert gid
    run(t())


# --------------------------------------------------------------- native mode
def native_harness(secret: str = SECRET) -> tuple[Harness, MockIdP]:
    idp = MockIdP(issuer="https://login.bank.example")
    ext = ExternalIssuer(issuer=idp.issuer, audience="marula-api", jwks=idp.jwks)
    return Harness(external_issuers={idp.issuer: ext}, internal_secret=secret), idp


async def register(h: Harness, monthly: str = "2000.00", secret: str = SECRET) -> httpx.Response:
    return await h.browser.post("/internal/grants", headers={"Authorization": f"Bearer {secret}"},
                                json={"customer": "thandi@example.com", "client_id": "kaya", "level": "bill_payer",
                                      "account": "acc_4821", "monthly_limit": monthly})


def use_token(h: Harness, token: str, gid: str) -> None:
    h.kaya.session.access_token, h.kaya.session.grant_id = token, gid


def test_grant_service_requires_the_idp_to_authenticate():
    async def t():
        h, _ = native_harness()
        assert (await register(h, secret="wrong")).status_code == 401
        off, _ = native_harness(secret="")
        assert (await register(off)).status_code == 404
        r = await h.browser.post("/internal/grants", headers={"Authorization": f"Bearer {SECRET}"},
                                 json={"customer": "thandi", "client_id": "copycat", "level": "bill_payer",
                                       "account": "acc_4821"})
        assert r.status_code == 400 and r.json()["error"] == "unauthorized_client"
    run(t())


def test_tokens_from_the_banks_own_authorisation_server_get_the_same_checks():
    async def t():
        h, idp = native_harness()
        g = (await register(h)).json()
        assert g["status"] == "active" and g["level"] == "bill_payer"
        tok = idp.access_token(client_id="kaya", grant_id=g["grant_id"], jkt=h.kaya.key.thumbprint,
                               details=g["authorization_details"])
        use_token(h, tok, g["grant_id"])
        assert await h.kaya.accounts()
        assert (await h.kaya.pay(*WATER, "640.00"))["outcome"] == "paid"
        # the IdP checks status before refreshing
        st = await h.browser.get(f"/internal/grants/{g['grant_id']}", headers={"Authorization": f"Bearer {SECRET}"})
        assert st.json()["spent_this_month"] == "640.00"
        # the customer pauses in the bank app: the IdP's still-valid token stops working at once
        await h.login()
        await h.grant_action(g["grant_id"], "pause")
        with pytest.raises(ValetError) as ei:
            await h.kaya.accounts()
        assert ei.value.error == "grant_paused"
    run(t())


def test_native_tokens_are_checked_for_issuer_binding_and_agent():
    async def t():
        h, idp = native_harness()
        g = (await register(h)).json()
        good = dict(client_id="kaya", grant_id=g["grant_id"], jkt=h.kaya.key.thumbprint, details=g["authorization_details"])
        stranger = MockIdP(issuer="https://evil.example")
        for tok, why in [(stranger.access_token(**good), "issuer"),
                         (idp.access_token(**{**good, "jkt": "someone-elses-key"}), "binding"),
                         (idp.access_token(**{**good, "client_id": "copycat"}), "agent"),
                         (idp.access_token(**good, audience="other-api"), "audience")]:
            use_token(h, tok, g["grant_id"])
            with pytest.raises(ValetError) as ei:
                await h.kaya.accounts()
            assert ei.value.status == 401, why
    run(t())


def test_native_tokens_cannot_widen_what_the_customer_consented_to():
    async def t():
        h, idp = native_harness()
        g = (await register(h, monthly="1000.00")).json()
        wider = [{**d, "limits": {"per_month": {"amount": "99999.00", "currency": "ZAR"}}} if d["type"] == "valet_payments"
                 else d for d in g["authorization_details"]]
        assert L.monthly_limit(wider) == 99_999_00                    # the token really does claim more
        use_token(h, idp.access_token(client_id="kaya", grant_id=g["grant_id"], jkt=h.kaya.key.thumbprint,
                                      details=wider), g["grant_id"])
        held = await h.kaya.pay(*WATER, "1500.00")
        assert held["outcome"] == "approval_pending" and "R1,000.00" in held["reason"]
    run(t())


def test_native_single_use_approval_from_the_banks_own_ciba():
    async def t():
        h, idp = native_harness()
        g = (await register(h)).json()
        use_token(h, idp.access_token(client_id="kaya", grant_id=g["grant_id"], jkt=h.kaya.key.thumbprint,
                                      details=g["authorization_details"]), g["grant_id"])
        body = {"from_account": POWER[0], "to": {"name": POWER[1], "account": POWER[2]}, "amount": "1250.00",
                "reference": "Oct"}
        with pytest.raises(ValetError) as ei:
            await h.kaya.call("POST", "/api/payments", body)
        assert ei.value.error == "approval_required"
        offered = ei.value.body["authorization_details"]
        # the bank's IdP ran the approval (e.g. Auth0 CIBA with RAR, Guardian push) and issued a one-off token
        once = idp.access_token(client_id="kaya", grant_id=g["grant_id"], jkt=h.kaya.key.thumbprint, details=offered,
                                jti="once-1")
        assert (await h.kaya.call("POST", "/api/payments", body, token=once))["status"] == "paid"
        with pytest.raises(ValetError) as ei:
            await h.kaya.call("POST", "/api/payments", body, token=once)
        assert ei.value.error == "approval_invalid"
        # an approval token for something the bank never offered is refused
        made_up = [{**offered[0], "to": {"name": "Fraudster", "account": "1"}}]
        fake = idp.access_token(client_id="kaya", grant_id=g["grant_id"], jkt=h.kaya.key.thumbprint, details=made_up)
        with pytest.raises(ValetError) as ei:
            await h.kaya.call("POST", "/api/payments", {**body, "to": {"name": "Fraudster", "account": "1"}}, token=fake)
        assert ei.value.error == "approval_invalid"
        assert h.bank.store.spent(g["grant_id"]) == 0
    run(t())


def test_agent_learns_its_grant_from_the_bank_when_the_idp_has_no_rar():
    async def t():
        h, idp = native_harness()
        g = (await register(h, monthly="1000.00")).json()
        # a token like Keycloak's: valet_grant and key binding, but no authorization_details
        use_token(h, idp.access_token(client_id="kaya", grant_id=g["grant_id"], jkt=h.kaya.key.thumbprint, details=[]),
                  g["grant_id"])
        mine = await h.kaya.grant()
        assert mine["grant_id"] == g["grant_id"] and mine["level"] == "bill_payer" and mine["status"] == "active"
        assert mine["authorization_details"] == g["authorization_details"]      # what the customer chose, from the bank
        await h.kaya.pay(*WATER, "640.00")
        assert (await h.kaya.grant())["spent_this_month"] == "640.00"
        await h.login()
        await h.grant_action(g["grant_id"], "pause")
        with pytest.raises(ValetError) as ei:                                   # paused means paused, even for this
            await h.kaya.grant()
        assert ei.value.error == "grant_paused"
    run(t())
