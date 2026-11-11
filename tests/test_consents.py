"""
The Consent Service (docs/consent-service-openapi.yaml): a standard consent model any application can use.

Tokens come from a mock of the bank's IdP (RS256, as Keycloak signs). The customer's approval goes through the same
hand-off Keycloak uses, with the consent_id the app created first.
"""
from __future__ import annotations

import asyncio
import re
import time
import uuid
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

SAST = ZoneInfo("Africa/Johannesburg")

import httpx
import jwt
import pytest

from valet.bank.consents import period_bounds
from valet.bank.tokens import ExternalIssuer
from valet.common.crypto import Key
from valet.common.dpop import make_proof
from valet.harness import BANK, Harness
from valet.testing.mock_idp import MockIdP

HANDOFF = "handoff-test-secret-0123456789-abcdef"
IDP_RETURN = "http://idp.test/realms/marula/"


def run(coro):
    return asyncio.run(coro)


def when(days: float) -> str:
    return (datetime.now(SAST) + timedelta(days=days)).replace(microsecond=0).isoformat()


AIS = {"authorization_details": [{"type": "account_information",
                                  "actions": ["read_accounts_basic", "read_balances", "read_transactions_detail"]}],
       "purpose": {"code": "affordability_assessment"}, "expires_at": when(180)}
GYM = {"authorization_details": [{
    "type": "recurring_payment", "actions": ["initiate_payment"],
    "creditor": {"name": "Acme Gym", "account": {"scheme": "za_bank_account", "identification": "62000000000"}},
    "control_parameters": {"max_individual_amount": {"amount": "750.00", "currency": "ZAR"},
                           "periodic_limits": [{"period_type": "Month", "period_alignment": "Calendar",
                                                "max_amount": {"amount": "750.00", "currency": "ZAR"}, "max_count": 1}]}}],
    "purpose": {"code": "subscription_payment"}, "expires_at": when(365)}
AGENT = {"authorization_details": [{
    "type": "delegated_action", "actions": ["transfer_between_own_accounts"],
    "control_parameters": {"max_individual_amount": {"amount": "5000.00", "currency": "ZAR"},
                           "periodic_limits": [{"period_type": "Month", "period_alignment": "Calendar",
                                                "max_amount": {"amount": "6000.00", "currency": "ZAR"}}],
                           "step_up_above": {"amount": "2000.00", "currency": "ZAR"}}}],
    "purpose": {"code": "automated_savings"}, "expires_at": when(90),
    "actor": {"type": "ai_agent", "id": "did:web:agents.acme.example:assistant", "display_name": "Acme Assistant"}}


class World:
    def __init__(self) -> None:
        self.idp = MockIdP(issuer="http://idp.test/realms/marula")
        ext = ExternalIssuer(issuer=self.idp.issuer, audience="marula-api", jwks=self.idp.jwks)
        self.h = Harness(external_issuers={self.idp.issuer: ext}, handoff_secret=HANDOFF,
                         handoff_idps={"keycloak:marula": IDP_RETURN})
        self.svc = self.h.bank.consents
        self.svc.deliver_inline = True
        self.app_key = Key.generate()

    def client_token(self, scope: str = "consents:write consents:read", client: str = "acme-budgeting",
                     aud: str = "valet-consent") -> dict[str, str]:
        now = int(time.time())
        tok = self.idp.sign({"iss": self.idp.issuer, "aud": aud, "azp": client, "scope": scope, "iat": now,
                             "exp": now + 300, "sub": "service-account"}, typ="at+jwt")
        return {"Authorization": f"Bearer {tok}"}

    async def create(self, body: dict, key: str | None = None, **kw) -> httpx.Response:
        return await self.h.browser.post("/consent/v1/consents", json=body, headers={
            **self.client_token(**kw), "x-idempotency-key": key or str(uuid.uuid4())})

    async def approve(self, consent_id: str, decision: str = "allow", client: str = "acme-budgeting",
                      account: str = "acc_4821") -> httpx.Response:
        now = int(time.time())
        ticket = jwt.encode({"iss": "keycloak:marula", "aud": BANK, "iat": now, "exp": now + 300,
                             "nonce": uuid.uuid4().hex, "customer": "thandi", "email": "thandi@example.com",
                             "client_id": client, "return_to": IDP_RETURN + "login-actions/x", "consent_id": consent_id},
                            HANDOFF, algorithm="HS256")
        page = await self.h.browser.get("/handoff/consent", params={"ticket": ticket})
        assert page.status_code == 200, page.text
        return await self.h.browser.post("/handoff/decision", data={"ticket": ticket, "account": account,
                                                                    "decision": decision})

    def app_token(self, consent_id: str, client: str = "acme-budgeting") -> str:
        return self.idp.access_token(client_id=client, grant_id=consent_id, jkt=self.app_key.thumbprint, details=[])

    async def api(self, method: str, path: str, token: str, body=None) -> httpx.Response:
        url = BANK + path
        return await self.h.browser.request(method, path, json=body, headers={
            "Authorization": f"DPoP {token}", "DPoP": make_proof(self.app_key, method, url, access_token=token)})

    async def decide(self, body: dict) -> dict:
        r = await self.h.browser.post("/consent/v1/consent-decisions", json=body,
                                      headers=self.client_token("consents:decide", client="payments-api"))
        assert r.status_code == 200, r.text
        return r.json()


def result_of(page: httpx.Response) -> dict:
    tok = re.search(r'name="valet_result" value="([^"]+)"', page.text).group(1)
    return jwt.decode(tok, HANDOFF, algorithms=["HS256"], audience="keycloak:marula")


# ------------------------------------------------------------------ lifecycle, end to end
def test_consent_lifecycle_create_authorise_use_revoke():
    async def t():
        w = World()
        r = await w.create(AIS, key="idem-key-0001")
        assert r.status_code == 201 and r.headers["location"].endswith(r.json()["consent_id"])
        c = r.json()
        assert c["status"] == "AwaitingAuthorisation" and c["resources"] == [] and re.match(r"^cns_[A-Za-z0-9]{24}$", c["consent_id"])
        # idempotent retry returns the same consent; same key with another body is a conflict
        again = await w.create(AIS, key="idem-key-0001")
        assert again.status_code == 200 and again.json()["consent_id"] == c["consent_id"]
        assert (await w.create(GYM, key="idem-key-0001")).status_code == 409
        # no token works before the customer approves
        early = await w.api("GET", "/ob/v1/accounts", w.app_token(c["consent_id"]))
        assert early.status_code == 403 and early.json()["detail"] == "consent_not_authorised"
        # the customer approves at the bank (reached through the IdP); the result names the consent
        res = result_of(await w.approve(c["consent_id"]))
        assert res["decision"] == "allow" and res["grant_id"] == c["consent_id"]
        got = (await w.h.browser.get(f"/consent/v1/consents/{c['consent_id']}", headers=w.client_token())).json()
        assert got["status"] == "Authorised" and got["resources"][0]["display"] == "Cheque account ••4821"
        assert "_account" not in got["resources"][0] and got["resources"][0]["resource_id"] != "acc_4821"
        tok = w.app_token(c["consent_id"])
        accts = (await w.api("GET", "/ob/v1/accounts", tok)).json()["accounts"]
        assert accts[0]["balance"]["amount"] == "18430.55"
        tx = await w.api("GET", f"/ob/v1/accounts/{accts[0]['account_id']}/transactions", tok)
        assert tx.status_code == 200 and tx.json()["transactions"]
        # payments are not in this consent
        pay = await w.api("POST", "/ob/v1/payments", tok, {"from_account": accts[0]["account_id"],
                                                           "amount": {"amount": "10.00", "currency": "ZAR"}})
        assert pay.status_code == 403
        # the customer revokes in the bank app: the still-valid token stops at once, and the app is told
        await w.h.login()
        assert (await w.h.browser.delete(f"/consent/v1/customers/me/consents/{c['consent_id']}")).status_code == 204
        stopped = await w.api("GET", "/ob/v1/accounts", tok)
        assert stopped.status_code == 403 and stopped.json()["detail"] == "consent_revoked"
        events = w.h.bank.store.q("SELECT token FROM consent_events WHERE consent_id=? ORDER BY created", c["consent_id"])
        jwks = (await w.h.browser.get("/consent/v1/jwks")).json()["keys"][0]
        last = jwt.decode(events[-1]["token"], jwt.PyJWK(jwks).key, algorithms=["ES256"], audience="acme-budgeting")
        ev = next(iter(last["events"].values()))
        assert ev["status"] == "Revoked" and ev["previous_status"] == "Authorised" and ev["status_reason"] == "revoked_by_customer"
        assert w.h.bank.receipts.verify_chain()["ok"]
    run(t())


def test_customer_decline_and_authorisation_window():
    async def t():
        w = World()
        c = (await w.create(AIS)).json()
        assert result_of(await w.approve(c["consent_id"], decision="deny"))["decision"] == "deny"
        assert w.svc.row(c["consent_id"])["status"] == "Rejected"
        late = (await w.create(AIS)).json()
        w.h.bank.store.x("UPDATE consents SET authorisation_expires=? WHERE id=?", time.time() - 1, late["consent_id"])
        now = int(time.time())
        ticket = jwt.encode({"iss": "keycloak:marula", "aud": BANK, "iat": now, "exp": now + 300, "nonce": "n-late",
                             "customer": "thandi", "client_id": "acme-budgeting", "return_to": IDP_RETURN + "x",
                             "consent_id": late["consent_id"]}, HANDOFF, algorithm="HS256")
        page = await w.h.browser.get("/handoff/consent", params={"ticket": ticket})
        assert page.status_code == 400 and "no longer waiting" in page.text
        assert w.svc.row(late["consent_id"])["status"] == "Expired"
        assert w.svc.row(late["consent_id"])["status_reason"] == "authorisation_window_elapsed"
    run(t())


def test_another_client_cannot_see_use_or_approve_someone_elses_consent():
    async def t():
        w = World()
        w.svc.clients["other-app"] = type(w.svc.clients["acme-budgeting"])("other-app", "Other App")
        c = (await w.create(AIS)).json()
        assert (await w.h.browser.get(f"/consent/v1/consents/{c['consent_id']}",
                                      headers=w.client_token(client="other-app"))).status_code == 404
        now = int(time.time())
        ticket = jwt.encode({"iss": "keycloak:marula", "aud": BANK, "iat": now, "exp": now + 300, "nonce": "n1",
                             "customer": "thandi", "client_id": "other-app", "return_to": IDP_RETURN + "x",
                             "consent_id": c["consent_id"]}, HANDOFF, algorithm="HS256")
        assert (await w.h.browser.get("/handoff/consent", params={"ticket": ticket})).status_code == 400
        result_of(await w.approve(c["consent_id"]))
        d = await w.api("GET", "/ob/v1/accounts", w.app_token(c["consent_id"], client="other-app"))
        assert d.status_code == 403 and d.json()["detail"] == "client_mismatch"
    run(t())


# ------------------------------------------------------------------ validation
@pytest.mark.parametrize("body,status,code,pointer", [
    ({**AIS, "purpose": {"code": "mining_crypto"}}, 422, "unknown_purpose", "/purpose/code"),
    ({**GYM, "purpose": {"code": "affordability_assessment"}}, 422, "purpose_not_allowed_for_type", "/authorization_details/0/type"),
    ({**AIS, "expires_at": when(800)}, 422, "expiry_exceeds_max", "/expires_at"),
    ({**AIS, "expires_at": when(-1)}, 422, "expiry_in_past", "/expires_at"),
    ({k: v for k, v in AGENT.items() if k != "actor"}, 422, "actor_required", "/actor"),
    ({**AIS, "authorization_details": [{"type": "account_information", "actions": ["move_money"]}]}, 400,
     "invalid_authorization_details", "/authorization_details/0/actions"),
    ({**AIS, "authorization_details": [{"type": "crypto_trading", "actions": ["buy"]}]}, 422, "unsupported_type",
     "/authorization_details/0/type"),
    ({**AIS, "favourite_colour": "teal"}, 400, "invalid_request", "/favourite_colour"),
])
def test_requests_that_break_the_rules_get_problem_details(body, status, code, pointer):
    async def t():
        r = await World().create(body)
        assert r.status_code == status and r.headers["content-type"].startswith("application/problem+json")
        assert r.json()["error_code"] == code and r.json()["errors"][0]["pointer"] == pointer
    run(t())


def test_client_tokens_need_the_right_issuer_audience_and_scope():
    async def t():
        w = World()
        assert (await w.create(AIS, scope="consents:read")).status_code == 403
        assert (await w.create(AIS, aud="marula-api")).status_code == 401
        assert (await w.create(AIS, client="not-onboarded")).status_code == 403
        stranger = MockIdP(issuer="http://evil.test")
        now = int(time.time())
        forged = stranger.sign({"iss": stranger.issuer, "aud": "valet-consent", "azp": "acme-budgeting",
                                "scope": "consents:write", "iat": now, "exp": now + 60})
        r = await w.h.browser.post("/consent/v1/consents", json=AIS, headers={"Authorization": f"Bearer {forged}",
                                                                             "x-idempotency-key": "k" * 10})
        assert r.status_code == 401
        no_key = await w.h.browser.post("/consent/v1/consents", json=AIS, headers=w.client_token())
        assert no_key.status_code == 400
        # only resource servers may ask for decisions
        r = await w.h.browser.post("/consent/v1/consent-decisions", json={}, headers=w.client_token())
        assert r.status_code == 403
    run(t())


# ------------------------------------------------------------------ the decision engine
def test_subscription_limits_reserve_confirm_and_release():
    async def t():
        w = World()
        c = (await w.create(GYM)).json()
        result_of(await w.approve(c["consent_id"]))
        res = w.svc.row(c["consent_id"])["resources"][0]["resource_id"]
        base = {"consent_id": c["consent_id"], "client_id": "acme-budgeting", "type": "recurring_payment",
                "action": "initiate_payment", "resource": {"resource_type": "account", "resource_id": res},
                "context": {"creditor_account": "62000000000"}}
        too_big = await w.decide({**base, "amount": {"amount": "751.00", "currency": "ZAR"}})
        assert too_big == {"decision": "deny", "reason": "limit_exceeded", "cache_ttl_seconds": 0}
        wrong_payee = await w.decide({**base, "amount": {"amount": "750.00", "currency": "ZAR"},
                                      "context": {"creditor_account": "99999"}})
        assert wrong_payee["reason"] == "action_not_granted"
        first = await w.decide({**base, "amount": {"amount": "750.00", "currency": "ZAR"}, "reserve": True})
        assert first["decision"] == "permit" and first["decision_id"]
        held = await w.decide({**base, "amount": {"amount": "1.00", "currency": "ZAR"}, "reserve": True})
        assert held["reason"] == "limit_exceeded"                       # the reservation counts against the limit
        hdr = w.client_token("consents:decide", client="payments-api")
        assert (await w.h.browser.patch(f"/consent/v1/consent-decisions/{first['decision_id']}",
                                        json={"outcome": "released"}, headers=hdr)).status_code == 204
        assert (await w.h.browser.patch(f"/consent/v1/consent-decisions/{first['decision_id']}",
                                        json={"outcome": "confirmed"}, headers=hdr)).status_code == 409
        again = await w.decide({**base, "amount": {"amount": "750.00", "currency": "ZAR"}, "reserve": True})
        assert again["decision"] == "permit"                            # released money is back
        await w.h.browser.patch(f"/consent/v1/consent-decisions/{again['decision_id']}", json={"outcome": "confirmed"},
                                headers=hdr)
        usage = (await w.h.browser.get(f"/consent/v1/consents/{c['consent_id']}/usage", headers=w.client_token())).json()
        assert usage["limits"][0]["used_amount"]["amount"] == "750.00" and usage["limits"][0]["used_count"] == 1
        # once a month: a second collection is refused even within the amount
        assert (await w.decide({**base, "amount": {"amount": "1.00", "currency": "ZAR"}}))["reason"] == "limit_exceeded"
    run(t())


def test_ai_agent_delegation_needs_the_named_actor_and_steps_up_large_amounts():
    async def t():
        w = World()
        c = (await w.create(AGENT)).json()
        assert c["actor"]["id"] == "did:web:agents.acme.example:assistant"
        page = await w.h.browser.get("/handoff/consent", params={"ticket": jwt.encode({
            "iss": "keycloak:marula", "aud": BANK, "iat": int(time.time()), "exp": int(time.time()) + 300, "nonce": "nz",
            "customer": "thandi", "client_id": "acme-budgeting", "return_to": IDP_RETURN + "x",
            "consent_id": c["consent_id"]}, HANDOFF, algorithm="HS256")})
        assert "Acme Assistant" in page.text and "needs your approval" in page.text
        result_of(await w.approve(c["consent_id"]))
        base = {"consent_id": c["consent_id"], "client_id": "acme-budgeting", "type": "delegated_action",
                "action": "transfer_between_own_accounts", "actor_id": "did:web:agents.acme.example:assistant"}
        ok = await w.decide({**base, "amount": {"amount": "1500.00", "currency": "ZAR"}})
        assert ok["decision"] == "permit"
        assert (await w.decide({**base, "amount": {"amount": "2500.00", "currency": "ZAR"}}))["decision"] == "step_up_required"
        assert (await w.decide({**base, "actor_id": "did:web:evil.example:bot",
                                "amount": {"amount": "10.00", "currency": "ZAR"}}))["reason"] == "actor_mismatch"
        assert (await w.decide({**base, "actor_id": None, "amount": {"amount": "10.00", "currency": "ZAR"}}))["reason"] == "actor_mismatch"
        assert (await w.decide({**base, "amount": {"amount": "5000.01", "currency": "ZAR"}}))["reason"] == "limit_exceeded"
        assert (await w.decide({**base, "action": "pay_existing_beneficiary",
                                "amount": {"amount": "10.00", "currency": "ZAR"}}))["reason"] == "action_not_granted"
    run(t())


def test_superseding_consent_revokes_the_old_one_when_approved():
    async def t():
        w = World()
        old = (await w.create(AIS)).json()
        result_of(await w.approve(old["consent_id"]))
        new = (await w.create({**AIS, "supersedes": old["consent_id"]})).json()
        assert w.svc.row(old["consent_id"])["status"] == "Authorised"     # nothing changes until the customer approves
        result_of(await w.approve(new["consent_id"]))
        o = w.svc.row(old["consent_id"])
        assert o["status"] == "Revoked" and o["status_reason"] == "superseded" and o["superseded_by"] == new["consent_id"]
    run(t())


def test_calendar_and_consent_aligned_periods():
    sast = ZoneInfo("Africa/Johannesburg")   # periods are in South African time, whatever the machine's zone (CI is UTC)
    at = lambda ts: datetime.fromtimestamp(ts, sast)
    t0 = datetime(2026, 11, 11, 10, 0, tzinfo=sast).timestamp()
    s, e = period_bounds("Month", "Calendar", 0, t0)
    assert at(s) == datetime(2026, 11, 1, tzinfo=sast) and at(e) == datetime(2026, 12, 1, tzinfo=sast)
    s, e = period_bounds("Week", "Calendar", 0, t0)
    assert e - s == 7 * 86400 and at(s).weekday() == 0 and at(s).hour == 0
    anchor = datetime(2026, 1, 31, 9, 0, tzinfo=sast).timestamp()
    s, e = period_bounds("Month", "Consent", anchor, datetime(2026, 3, 5, tzinfo=sast).timestamp())
    assert at(s).month == 2 and at(e).month == 3   # Jan 31 -> Feb 28 -> Mar 28
