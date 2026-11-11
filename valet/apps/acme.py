"""
Acme Budgeting (fictional): a third-party app that uses the bank's Consent Service, Open Banking style.

  1 client-credentials token from the bank's IdP (private_key_jwt + DPoP)   scope consents:write
  2 POST /consent/v1/consents                                              -> consent_id, AwaitingAuthorisation
  3 PAR to the bank's IdP with consent_id; the customer signs in at the IdP and approves on the bank's screen
  4 authorization code -> DPoP-bound token whose valet_grant claim is the consent_id
  5 call the bank's open APIs; the bank asks the Consent Service on every call
  6 receive signed consent events (RFC 8417) when the customer stops access in the bank app

    uvicorn valet.apps.acme:get_app --factory --port 8002
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
import uuid
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

SAST = ZoneInfo("Africa/Johannesburg")
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from jinja2 import Environment, select_autoescape

from ..common.crypto import Key, b64u, jwk_thumbprint, random_id
from ..common.dpop import make_proof

CLIENT_ID = "acme-budgeting"


def when(days: float) -> str:
    return (datetime.now(SAST) + timedelta(days=days)).replace(microsecond=0).isoformat()


def scenarios() -> dict[str, dict[str, Any]]:
    return {
        "affordability": {
            "label": "Check affordability (read 6 months of transactions)",
            "request": {
                "authorization_details": [{
                    "type": "account_information",
                    "actions": ["read_accounts_basic", "read_balances", "read_transactions_detail"],
                    "constraints": {"transactions_from": when(-180), "transactions_to": when(1),
                                    "account_types": ["cheque", "savings"]}}],
                "purpose": {"code": "affordability_assessment"}, "expires_at": when(180),
                "metadata": {"application_ref": "LOAN-2026-004211"}}},
        "gym": {
            "label": "Set up Acme Gym subscription (R750 a month, once a month)",
            "request": {
                "authorization_details": [{
                    "type": "recurring_payment", "actions": ["initiate_payment"],
                    "creditor": {"name": "Acme Gym (Pty) Ltd", "account": {"scheme": "za_bank_account",
                                                                          "identification": "62000000000",
                                                                          "branch_code": "250655"}},
                    "control_parameters": {"max_individual_amount": {"amount": "750.00", "currency": "ZAR"},
                                           "periodic_limits": [{"period_type": "Month", "period_alignment": "Calendar",
                                                                "max_amount": {"amount": "750.00", "currency": "ZAR"},
                                                                "max_count": 1}]}}],
                "purpose": {"code": "subscription_payment"}, "expires_at": when(365)}},
    }


PAGE = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Acme Budgeting</title><style>
body{margin:0;background:#F4F2EE;font-family:system-ui,sans-serif;color:#1d1b19;font-size:15px}
.wrap{max-width:980px;margin:0 auto;padding:24px;display:grid;grid-template-columns:1.1fr .9fr;gap:20px}
h1{margin:0 0 4px;font-size:22px}.sub{color:#6b655e;font-size:13px}.card{background:#fff;border-radius:14px;padding:16px;margin-bottom:14px;border:1px solid #e6e1da}
button{font:inherit;font-weight:600;border-radius:10px;padding:10px 12px;border:1px solid #d6cfc5;background:#fff;cursor:pointer;width:100%;text-align:left;margin:4px 0}
button.p{background:#C2410C;color:#fff;border:0}.log div{padding:8px 10px;border-radius:8px;margin:4px 0;background:#F7F5F2}
.ok{border-left:4px solid #15803d}.no{border-left:4px solid #b91c1c}.ev{border-left:4px solid #7c3aed}
pre{white-space:pre-wrap;font-size:11px;background:#F7F5F2;padding:10px;border-radius:8px;max-height:280px;overflow:auto}
.pill{font-size:12px;font-weight:700;border-radius:99px;padding:3px 9px;background:#eee}.Authorised{background:#dcfce7;color:#166534}
.Revoked,.Rejected,.Expired{background:#fee2e2;color:#991b1b}.AwaitingAuthorisation{background:#fef3c7;color:#92400e}
</style></head><body><div class="wrap"><div>
<h1>◆ Acme Budgeting</h1><div class="sub">A fictional third-party app using Marula Bank's Consent Service through Keycloak</div><br>
<div class="card"><b>Connect</b>{% for k, s in scenarios.items() %}<form method="post" action="/connect/{{ k }}"><button class="p">{{ s.label }}</button></form>{% endfor %}</div>
<div class="card"><b>Use the access</b>
<form method="post" action="/do/accounts"><button>Read accounts and balances</button></form>
<form method="post" action="/do/transactions"><button>Read transactions</button></form>
<form method="post" action="/do/pay"><button>Collect gym subscription · R750</button></form>
<form method="post" action="/do/pay_more"><button>Try to collect R1,200 (over the per-payment cap)</button></form>
<form method="post" action="/do/revoke"><button>Cancel the consent from Acme's side</button></form></div>
<div class="card log"><b>Activity</b>{% for m in log|reverse %}<div class="{{ m.kind }}">{{ m.text }}</div>{% endfor %}</div></div>
<div><div class="card"><b>Consent</b> {% if consent %}<span class="pill {{ consent.status }}">{{ consent.status }}</span>{% endif %}
{% if consent %}<pre>{{ consent_json }}</pre>{% else %}<div class="sub">None yet</div>{% endif %}</div>
<div class="card log"><b>Signed events from the bank</b> <span class="sub">(webhook, RFC 8417, signature checked)</span><div id="events">
{% for e in events|reverse %}<div class="ev">{{ e }}</div>{% else %}<div class="sub">None yet</div>{% endfor %}</div></div></div></div>
<script>let n={{ events|length }};setInterval(async()=>{try{const r=await fetch('/events.json');const j=await r.json();if(j.count!==n){location.reload()}}catch(e){}},1500)</script>
</body></html>"""


def create_acme_app(data_dir: Path | None = None, http: httpx.AsyncClient | None = None,
                    idp_discovery: str | None = None, bank_url: str | None = None, public_url: str | None = None) -> FastAPI:
    data_dir = data_dir or Path(os.environ.get("VALET_DATA", "./data"))
    bank_url = (bank_url or os.environ.get("BANK_INTERNAL_URL", "http://localhost:8000")).rstrip("/")
    public_url = (public_url or os.environ.get("ACME_PUBLIC_URL", "http://localhost:8002")).rstrip("/")
    idp_discovery = idp_discovery or os.environ.get(
        "ACME_IDP_DISCOVERY", "http://localhost:8080/realms/marula/.well-known/openid-configuration")
    key = Key.load_or_create(data_dir / "apps" / "acme.pem")
    (data_dir / "apps" / "acme.json").write_text(json.dumps({"client_id": CLIENT_ID, "jwk": key.jwk}))
    http = http or httpx.AsyncClient(timeout=15)
    st: dict[str, Any] = {"meta": None, "token": None, "consent_id": None, "pending": None, "log": [], "events": [],
                          "consent": None, "account": None}
    env = Environment(autoescape=select_autoescape())
    redirect_uri = public_url + "/callback"
    app = FastAPI(title="Acme Budgeting (fictional)")

    def say(text: str, kind: str = "") -> None:
        st["log"].append({"text": text, "kind": kind})

    async def meta() -> dict[str, Any]:
        if not st["meta"]:
            st["meta"] = (await http.get(idp_discovery)).json()
        return st["meta"]

    def assertion(aud: str) -> dict[str, str]:
        now = int(time.time())
        a = key.sign({"iss": CLIENT_ID, "sub": CLIENT_ID, "aud": aud, "iat": now, "exp": now + 60, "jti": random_id("ca")},
                     headers={"kid": jwk_thumbprint(key.jwk)})
        return {"client_id": CLIENT_ID, "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": a}

    async def token_request(data: dict[str, Any]) -> dict[str, Any]:
        m = await meta()
        r = await http.post(m["token_endpoint"], data={**data, **assertion(m["issuer"])},
                            headers={"DPoP": make_proof(key, "POST", m["token_endpoint"])})
        if r.status_code >= 400:
            raise RuntimeError(f"token endpoint: {r.status_code} {r.text[:200]}")
        return r.json()

    async def bank(method: str, path: str, token: str, body: Any = None, headers: dict[str, str] | None = None) -> httpx.Response:
        url = bank_url + path
        return await http.request(method, url, json=body, headers={"Authorization": f"DPoP {token}",
                                                                   "DPoP": make_proof(key, method, url, access_token=token),
                                                                   "x-fapi-interaction-id": str(uuid.uuid4()),
                                                                   **(headers or {})})

    async def refresh_consent() -> None:
        if st["consent_id"]:
            tok = (await token_request({"grant_type": "client_credentials"}))["access_token"]
            r = await bank("GET", f"/consent/v1/consents/{st['consent_id']}", tok)
            st["consent"] = r.json() if r.status_code == 200 else st["consent"]

    @app.get("/", response_class=HTMLResponse)
    async def home():
        try:
            await refresh_consent()
        except Exception:  # noqa: BLE001  (the page still renders if the bank is down)
            pass
        return env.from_string(PAGE).render(scenarios=scenarios(), log=st["log"][-12:], events=st["events"][-8:],
                                            consent=st["consent"], consent_json=json.dumps(st["consent"], indent=2))

    @app.get("/events.json")
    async def events():
        return {"count": len(st["events"][-8:])}

    @app.post("/connect/{which}")
    async def connect(which: str):
        sc = scenarios()[which]
        try:
            tok = (await token_request({"grant_type": "client_credentials"}))["access_token"]
            r = await bank("POST", "/consent/v1/consents", tok, sc["request"],
                           headers={"x-idempotency-key": str(uuid.uuid4())})
            if r.status_code != 201:
                say(f"The bank refused the consent request: {r.json().get('title')} {r.json().get('detail', '')}", "no")
                return RedirectResponse("/", 303)
            c = r.json()
            st.update(consent_id=c["consent_id"], consent=c, token=None)
            say(f"Created consent {c['consent_id']} at the bank (status {c['status']}). No customer yet.", "ok")
            verifier = b64u(secrets.token_bytes(32))
            challenge = b64u(hashlib.sha256(verifier.encode()).digest())
            state = secrets.token_urlsafe(16)
            m = await meta()
            par = await http.post(m["pushed_authorization_request_endpoint"], data={
                "response_type": "code", "redirect_uri": redirect_uri, "scope": "openid", "state": state,
                "code_challenge": challenge, "code_challenge_method": "S256", "consent_id": c["consent_id"],
                **assertion(m["issuer"])})
            if par.status_code >= 400:
                say(f"Keycloak refused the request: {par.text[:160]}", "no")
                return RedirectResponse("/", 303)
            st["pending"] = {"state": state, "verifier": verifier}
            return RedirectResponse(m["authorization_endpoint"] + "?" + urlencode(
                {"client_id": CLIENT_ID, "request_uri": par.json()["request_uri"]}), 303)
        except (httpx.HTTPError, RuntimeError) as e:
            say(f"Couldn't reach the bank: {e}", "no")
            return RedirectResponse("/", 303)

    @app.get("/callback")
    async def callback(code: str = "", state: str = "", error: str = ""):
        p, st["pending"] = st["pending"], None
        if error or not p or state != p["state"]:
            say("You didn't approve, so Acme has no access." if error else "That sign-in link expired.", "no")
            return RedirectResponse("/", 303)
        body = await token_request({"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
                                    "code_verifier": p["verifier"]})
        st["token"] = body["access_token"]
        claims = jwt.decode(body["access_token"], options={"verify_signature": False})
        say(f"Keycloak issued Acme a DPoP-bound token pointing at consent {claims.get('valet_grant')}. "
            "Acme never saw your password.", "ok")
        return RedirectResponse("/", 303)

    def need_token() -> str | None:
        if not st["token"]:
            say("Connect first.", "no")
        return st["token"]

    @app.post("/do/{what}")
    async def do(what: str):
        if what == "revoke":
            if st["consent_id"]:
                tok = (await token_request({"grant_type": "client_credentials"}))["access_token"]
                r = await bank("DELETE", f"/consent/v1/consents/{st['consent_id']}", tok)
                say(f"Acme cancelled the consent (HTTP {r.status_code}).", "ok" if r.status_code == 204 else "no")
            return RedirectResponse("/", 303)
        tok = need_token()
        if not tok:
            return RedirectResponse("/", 303)
        if what == "accounts":
            r = await bank("GET", "/ob/v1/accounts", tok)
            if r.status_code == 200:
                accts = r.json()["accounts"]
                st["account"] = accts[0]["account_id"] if accts else None
                say("Accounts: " + ", ".join(f"{a['display']} R{a.get('balance', {}).get('amount', '?')}" for a in accts), "ok")
            else:
                say(f"The bank said no: {r.json().get('detail') or r.json().get('error_description')}", "no")
        elif what == "transactions":
            if not st["account"]:
                r0 = await bank("GET", "/ob/v1/accounts", tok)
                st["account"] = (r0.json().get("accounts") or [{}])[0].get("account_id") if r0.status_code == 200 else None
            r = await bank("GET", f"/ob/v1/accounts/{st['account']}/transactions", tok)
            if r.status_code == 200:
                tx = r.json()["transactions"]
                say(f"{len(tx)} transactions in the consented window: " +
                    ", ".join(f"{t['description']} R{t['amount']['amount']}" for t in tx[:4]), "ok")
            else:
                say(f"The bank said no: {r.json().get('detail') or r.json().get('error_description')}", "no")
        elif what in ("pay", "pay_more"):
            consent = st["consent"] or {}
            acct = (consent.get("resources") or [{}])[0].get("resource_id")
            amount = "750.00" if what == "pay" else "1200.00"
            r = await bank("POST", "/ob/v1/payments", tok, {
                "from_account": acct, "amount": {"amount": amount, "currency": "ZAR"},
                "creditor": {"name": "Acme Gym (Pty) Ltd", "account": {"identification": "62000000000"}},
                "reference": "ACME GYM"})
            if r.status_code == 200:
                say(f"Collected R{amount} for Acme Gym.", "ok")
            else:
                say(f"The bank said no: {r.json().get('detail') or r.json().get('error_description')}", "no")
        return RedirectResponse("/", 303)

    @app.post("/webhooks/consent")
    async def webhook(request: Request):
        raw = (await request.body()).decode()
        try:
            jwks = (await http.get(bank_url + "/consent/v1/jwks")).json()
            k = next(k for k in jwks["keys"] if k["kid"] == jwt.get_unverified_header(raw).get("kid"))
            claims = jwt.decode(raw, jwt.PyJWK(k).key, algorithms=["ES256"], audience=CLIENT_ID)
        except Exception as e:  # noqa: BLE001
            say(f"Rejected an event that failed signature checks: {e}", "no")
            return JSONResponse({"error": "invalid_event"}, status_code=400)
        ev = next(iter(claims["events"].values()))
        st["events"].append(f"{ev['changed_at'][11:19]} consent {ev['consent_id'][-6:]}: {ev['previous_status']} → "
                            f"{ev['status']} ({ev.get('status_reason')})")
        # Acme keeps its token on purpose: the demo then shows the bank refusing a token that is still valid.
        return JSONResponse({}, status_code=202)

    return app


def get_app() -> FastAPI:
    return create_acme_app()
