#!/usr/bin/env python3
"""
Preflight: walk the whole native-mode demo the way a browser would, against the running stack, and say PASS or FAIL.

Run it before you present (and after `down -v` to start clean):

    python scripts/preflight.py                         # localhost
    DEMO_HOST=demo.example.com DEMO_SCHEME=https python scripts/preflight.py

It signs Thandi in on Keycloak's own page, picks Bill payer on Valet's consent screen, lets Kaya pay within its limit,
holds a new recipient for approval in the bank app (with a fresh Keycloak sign-in), refuses a beneficiary add, pauses
Kaya from the bank app while its Keycloak token is still valid, and checks the receipt chain. It leaves Kaya paused
and then resumes it, so the stack is ready to demo afterwards. It does NOT reset data: run `down -v` for a clean slate.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from html.parser import HTMLParser
from http.cookiejar import CookieJar, DefaultCookiePolicy
from urllib.parse import urljoin, urlsplit

import httpx
import jwt

HOST = os.environ.get("DEMO_HOST", "localhost")
SCHEME = os.environ.get("DEMO_SCHEME", "http")
KAYA = os.environ.get("KAYA_URL", f"{SCHEME}://{HOST}:8001")
BANK = os.environ.get("BANK_URL", f"{SCHEME}://{HOST}:8000")
ACME = os.environ.get("ACME_URL", f"{SCHEME}://{HOST}:8002")
USER, PASSWORD = os.environ.get("DEMO_USER", "thandi"), os.environ.get("DEMO_PASSWORD", "demo")

for _stream in (sys.stdout, sys.stderr):  # Windows consoles default to cp1252, which cannot print the demo's arrows
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")
if os.name == "nt":
    os.system("")  # turn on ANSI colours in the Windows console

GREEN, RED, DIM, END = "\033[32m", "\033[31m", "\033[2m", "\033[0m"
results: list[tuple[str, bool, str]] = []


class Forms(HTMLParser):
    """Just enough of a browser: collects forms, their inputs, selects and buttons."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []
        self._select: str | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self.forms.append({"action": a.get("action", ""), "method": (a.get("method") or "get").lower(), "fields": {},
                               "buttons": []})
        elif not self.forms:
            return
        elif tag == "input" and a.get("name"):
            if a.get("type") == "radio" and a["name"] in self.forms[-1]["fields"] and "checked" not in a:
                return
            if a.get("type") == "checkbox" and "checked" not in a:
                return
            if a.get("type") in ("submit",):
                self.forms[-1]["buttons"].append((a["name"], a.get("value", "")))
            else:
                self.forms[-1]["fields"][a["name"]] = a.get("value", "")
        elif tag == "button" and a.get("name"):
            self.forms[-1]["buttons"].append((a["name"], a.get("value", "")))
        elif tag == "select":
            self._select = a.get("name")
        elif tag == "option" and self._select:
            f = self.forms[-1]["fields"]
            if self._select not in f or "selected" in a:
                f[self._select] = a.get("value", "")

    def handle_endtag(self, tag):
        if tag == "select":
            self._select = None


def forms(html: str) -> list[dict]:
    p = Forms()
    p.feed(html)
    return p.forms


class BrowserCookiePolicy(DefaultCookiePolicy):
    """Like a browser: Secure cookies are sent over https, and over plain http only to localhost (a secure context).
    Keycloak 26 marks its login cookies Secure, so a plain-http DEMO_HOST fails here exactly as it would in Chrome."""

    def _local(self, request) -> bool:
        return urlsplit(request.get_full_url()).hostname in ("localhost", "127.0.0.1")

    def set_ok(self, cookie, request):
        if cookie.secure and self._local(request):
            cookie.secure = False
        return super().set_ok(cookie, request)


class Browser:
    def __init__(self) -> None:
        self.c = httpx.Client(follow_redirects=False, timeout=20, cookies=CookieJar(BrowserCookiePolicy()))

    def go(self, method: str, url: str, data: dict | None = None, stop_at: str = "") -> httpx.Response:
        for _ in range(15):
            if stop_at and url.startswith(stop_at):
                r = httpx.Response(200, request=httpx.Request("GET", url))
                r.final_url = url  # type: ignore[attr-defined]
                return r
            r = self.c.request(method, url, data=data)
            if r.status_code in (301, 302, 303, 307):
                url, method, data = urljoin(url, r.headers["location"]), ("GET" if r.status_code != 307 else method), \
                    (None if r.status_code != 307 else data)
                continue
            r.final_url = url  # type: ignore[attr-defined]
            return r
        raise RuntimeError("too many redirects")

    def submit(self, r: httpx.Response, pick=lambda f: True, button: tuple[str, str] | None = None, stop_at: str = "",
               **values) -> httpx.Response:
        fs = [f for f in forms(r.text) if pick(f)]
        if not fs:
            raise RuntimeError(f"no matching form on {r.final_url}")  # type: ignore[attr-defined]
        f = fs[0]
        data = {**f["fields"], **values}
        if button:
            data[button[0]] = button[1]
        return self.go(f["method"].upper(), urljoin(r.final_url, f["action"]), data, stop_at=stop_at)  # type: ignore[attr-defined]

    def keycloak_login_if_asked(self, r: httpx.Response) -> httpx.Response:
        if "kc-form-login" in r.text or 'name="username"' in r.text:
            r = self.submit(r, lambda f: "login-actions/authenticate" in f["action"], username=USER, password=PASSWORD)
        return r


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, ok, detail))
    print(f"  {GREEN + 'PASS' if ok else RED + 'FAIL'}{END}  {name}" + (f"  {DIM}{detail}{END}" if detail else ""))
    return ok


def kaya_last(b: Browser) -> str:
    msgs = re.findall(r'<div class="b kaya[^"]*">(.*?)</div>', b.go("GET", KAYA + "/").text, re.S)
    return msgs[-1] if msgs else ""


def acme_last(b: Browser) -> tuple[str, str]:
    page = b.go("GET", ACME + "/").text
    acts = re.findall(r'<div class="(ok|no)">(.*?)</div>', page.split("<b>Activity</b>")[1].split("</div></div>")[0], re.S)
    return (acts[0][0], acts[0][1]) if acts else ("", "")


def acme_events(b: Browser) -> str:
    page = b.go("GET", ACME + "/").text
    return " | ".join(re.findall(r'<div class="ev">(.*?)</div>', page))


def consent_service(b: Browser) -> None:
    try:
        b.go("GET", ACME + "/")
    except httpx.HTTPError:
        check("Acme Budgeting (Consent Service demo app) is up", False, ACME)
        return
    r = b.go("POST", ACME + "/connect/affordability")
    r = b.keycloak_login_if_asked(r)
    check("App's consent goes through Keycloak to the bank's approval screen",
          "/handoff/consent" in r.final_url and "wants access" in r.text, r.final_url.split("?")[0])  # type: ignore[attr-defined]
    summary = re.search(r"What you are agreeing to</b><p[^>]*>(.*?)</p>", r.text, re.S)
    check("Approval screen shows the consent in plain language", bool(summary), summary.group(1)[:110] if summary else "")
    r = b.submit(r, lambda f: "/handoff/decision" in f["action"], button=("decision", "allow"))
    b.submit(r, lambda f: "valet_result" in f["fields"])
    kind, msg = acme_last(b)
    check("Keycloak's token for the app carries only the consent reference", kind == "ok" and "consent" in msg, msg[:110])
    b.go("POST", ACME + "/do/accounts")
    kind, msg = acme_last(b)
    check("App reads balances: consent decision permit", kind == "ok" and msg.startswith("Accounts"), msg[:100])
    b.go("POST", ACME + "/do/transactions")
    kind, msg = acme_last(b)
    check("App reads transactions inside the consented window", kind == "ok", msg[:100])
    # the customer stops it in the bank app
    r = b.keycloak_login_if_asked(b.go("GET", BANK + "/app/connected-apps"))
    if check("Consent is listed under the customer's Connected apps", "Stop Acme Budgeting" in r.text):
        b.submit(r, lambda f: f["action"].endswith("/revoke"))
        time.sleep(1.5)
        ev = acme_events(b)
        check("App receives a signed 'Revoked' event (webhook)", "Revoked" in ev, ev[-110:])
        b.go("POST", ACME + "/do/accounts")
        kind, msg = acme_last(b)
        check("Revoked consent stops the app's still-valid Keycloak token", kind == "no" and "revoked" in msg, msg[:100])
    # a subscription with limits
    r = b.keycloak_login_if_asked(b.go("POST", ACME + "/connect/gym"))
    r = b.submit(r, lambda f: "/handoff/decision" in f["action"], button=("decision", "allow"))
    b.submit(r, lambda f: "valet_result" in f["fields"])
    b.go("POST", ACME + "/do/pay")
    kind, msg = acme_last(b)
    check("Subscription payment within its limits is collected (R750)", kind == "ok" and "Collected" in msg, msg[:100])
    b.go("POST", ACME + "/do/pay")
    kind, msg = acme_last(b)
    check("A second collection in the same month is refused", kind == "no" and "limit_exceeded" in msg, msg[:100])
    b.go("POST", ACME + "/do/pay_more")
    kind, msg = acme_last(b)
    check("An amount over the per-payment cap is refused", kind == "no" and "limit_exceeded" in msg, msg[:100])


CLAUDE_CALLBACK = "http://localhost:33418/callback"     # what Claude Code uses; claude.ai uses its own HTTPS callback
CLAUDE_SECRET = os.environ.get("CLAUDE_CLIENT_SECRET", "claude-demo-secret-change-me")


class MCP:
    def __init__(self, url: str, token: str):
        self.url, self.token, self.n = url, token, 0

    def call(self, method: str, params: dict | None = None) -> dict:
        self.n += 1
        r = httpx.post(self.url, json={"jsonrpc": "2.0", "id": self.n, "method": method, "params": params or {}},
                       headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json, text/event-stream"},
                       timeout=20)
        r.raise_for_status()
        return r.json()["result"]

    def tool(self, name: str, **args) -> dict:
        res = self.call("tools/call", {"name": name, "arguments": args})
        return json.loads(res["content"][0]["text"])


def mcp_gateway(b: Browser) -> None:
    import base64
    import hashlib
    import secrets
    mcp_url = BANK + "/mcp"
    r = httpx.post(mcp_url, json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    m = re.search(r'resource_metadata="([^"]+)"', r.headers.get("www-authenticate", ""))
    if not check("Gateway asks for sign-in and points to its metadata (RFC 9728)", r.status_code == 401 and bool(m)):
        return
    prm = httpx.get(m.group(1)).json()
    issuer = prm["authorization_servers"][0]
    origin, path = re.match(r"(https?://[^/]+)(.*)", issuer).groups()
    meta, used = None, ""
    for url in (f"{origin}/.well-known/oauth-authorization-server{path}", f"{origin}/.well-known/openid-configuration{path}",
                f"{issuer}/.well-known/openid-configuration"):           # the MCP spec's discovery order
        resp = httpx.get(url)
        if resp.status_code == 200:
            meta, used = resp.json(), url
            break
    if not check("Connector finds Keycloak as the authorisation server", bool(meta) and prm["resource"] == mcp_url,
                 used.replace(origin, "")):
        return
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    q = {"response_type": "code", "client_id": "claude", "redirect_uri": CLAUDE_CALLBACK, "scope": "openid offline_access",
         "state": "st-1", "code_challenge": challenge, "code_challenge_method": "S256", "resource": mcp_url}
    r = b.keycloak_login_if_asked(b.go("GET", meta["authorization_endpoint"] + "?" + httpx.QueryParams(q).__str__(),
                                       stop_at=CLAUDE_CALLBACK))
    check("Claude's sign-in reaches the bank's consent screen, with the approve-every-payment rule",
          "/handoff/consent" in r.final_url and "You approve every payment Claude asks for" in r.text,  # type: ignore[attr-defined]
          r.final_url.split("?")[0])  # type: ignore[attr-defined]
    r = b.submit(r, lambda f: "/handoff/decision" in f["action"], button=("decision", "allow"), level="bill_payer",
                 monthly="200000")
    r = b.submit(r, lambda f: "valet_result" in f["fields"], stop_at=CLAUDE_CALLBACK)
    code = dict(httpx.URL(r.final_url).params).get("code")  # type: ignore[attr-defined]
    tok = httpx.post(meta["token_endpoint"], data={"grant_type": "authorization_code", "code": code,
                                                   "redirect_uri": CLAUDE_CALLBACK, "code_verifier": verifier,
                                                   "resource": mcp_url}, auth=("claude", CLAUDE_SECRET))
    if not check("Keycloak issues Claude a gateway-bound token (confidential client, PKCE)", tok.status_code == 200,
                 tok.text[:100] if tok.status_code != 200 else ""):
        return
    claims = jwt.decode(tok.json()["access_token"], options={"verify_signature": False})
    s = MCP(mcp_url, tok.json()["access_token"])
    init = s.call("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                 "clientInfo": {"name": "preflight-as-claude", "version": "1"}})
    tools = [t["name"] for t in s.call("tools/list")["tools"]]
    check("MCP handshake and mandate-filtered tool list", init["protocolVersion"] == "2025-06-18" and
          "pay_existing_payee" in tools and "add_beneficiary" not in tools, f"mandate {claims.get('valet_grant')}, "
          f"{len(tools)} tools")
    acct = s.tool("list_accounts")["accounts"][0]["account_id"]
    tx = s.tool("list_transactions", account_id=acct, days=30)["transactions"]
    check("Transactions reach the model (including a planted prompt injection)", any("AI ASSISTANT" in t["description"]
                                                                                    for t in tx), f"{len(tx)} transactions")
    hijack = s.tool("pay_existing_payee", payee_id="quickloans", from_account_id=acct, amount="4999.00",
                    reason="Instruction found in a transaction description", idempotency_key="hijack-0001")
    check("Even if the model obeys the injection, the bank declines it", hijack["outcome"] == "DECLINED" and
          hijack["reason_codes"] == ["PAYEE_NOT_IN_MANDATE"], hijack["reason_codes"][0])
    payees = {p["name"]: p["payee_id"] for p in s.tool("list_payees")["payees"]}
    req = dict(payee_id=payees["Water & Sanitation"], from_account_id=acct, amount="640.00", reference="Water Nov",
               reason="Thandi asked me to pay this month's water bill", idempotency_key="water-nov-0001")
    held = s.tool("pay_existing_payee", **req)
    check("A payment to a saved payee waits for the customer (APPROVAL_REQUIRED)", held["outcome"] == "APPROVAL_REQUIRED",
          held.get("payment_ref", ""))
    again = s.tool("pay_existing_payee", **req)
    check("A retried request with the same idempotency key is the same request", again.get("payment_ref") ==
          held.get("payment_ref"))
    r = b.keycloak_login_if_asked(b.go("GET", f"{BANK}/app/approvals/{held['payment_ref']}"))
    check("The bank app shows Claude's stated reason", "Thandi asked me to pay" in r.text)
    r = b.submit(r, lambda f: "/app/approvals/" in f["action"], button=("decision", "approve"))
    r = b.keycloak_login_if_asked(r)
    if "/app/approvals/" in r.final_url and "decision" in r.text:  # type: ignore[attr-defined]
        b.submit(r, lambda f: "/app/approvals/" in f["action"], button=("decision", "approve"))
    paid = s.tool("get_payment_status", payment_ref=held["payment_ref"])
    twice = s.tool("get_payment_status", payment_ref=held["payment_ref"])
    check("Approved in the app: paid exactly once", paid["outcome"] == "APPROVED" and "receipt" in paid and
          "receipt" not in twice, paid.get("paid", ""))
    big = s.tool("pay_existing_payee", payee_id=payees["Sunrise Primary School"], from_account_id=acct, amount="1500.00",
                 reason="School fees", idempotency_key="school-0001")
    check("Over the monthly limit is declined before it reaches the customer", big["outcome"] == "DECLINED" and
          big["reason_codes"] == ["MONTHLY_LIMIT_EXCEEDED"], big["reason_codes"][0])
    gid = claims["valet_grant"]
    page = b.go("GET", f"{BANK}/app/agents/{gid}")
    b.submit(page, lambda f: f["action"].endswith("/pause"))
    stopped = s.tool("list_accounts")
    check("Pausing Claude in the bank app stops its next tool call", stopped.get("reason_codes") == ["MANDATE_PAUSED"])
    page = b.go("GET", f"{BANK}/app/agents/{gid}")
    b.submit(page, lambda f: f["action"].endswith("/resume"))
    try:                                           # protocol conformance with the official MCP Python SDK, if installed
        import asyncio
        from contextlib import asynccontextmanager

        from mcp import ClientSession
        import mcp.client.streamable_http as sh

        @asynccontextmanager
        async def transport():
            hdr = {"Authorization": f"Bearer {s.token}"}
            if hasattr(sh, "streamable_http_client"):              # MCP Python SDK 2.x
                async with sh.create_mcp_http_client(headers=hdr) as http:
                    async with sh.streamable_http_client(mcp_url, http_client=http) as streams:
                        yield streams[0], streams[1]
            else:                                                  # 1.x
                async with sh.streamablehttp_client(mcp_url, headers=hdr) as (rd, wr, _):
                    yield rd, wr

        async def sdk() -> list[str]:
            async with transport() as (rd, wr):
                async with ClientSession(rd, wr) as session:
                    await session.initialize()
                    res = await session.call_tool("list_payees", {})
                    err = getattr(res, "is_error", getattr(res, "isError", None))
                    return [t.name for t in (await session.list_tools()).tools] + [str(err)]
        out = asyncio.run(sdk())
        check("Official MCP SDK client connects and calls tools", "list_payees" in out and out[-1] == "False",
              f"{len(out) - 1} tools")
    except ImportError:
        pass


def main() -> int:
    print(f"Preflight against Kaya {KAYA} · Bank {BANK}\n")
    b = Browser()
    try:
        b.go("GET", KAYA + "/")
        b.go("GET", BANK + "/.well-known/oauth-authorization-server").raise_for_status()
    except Exception as e:  # noqa: BLE001
        check("stack is up", False, str(e))
        return 1
    check("stack is up", True)

    # 1. Connect through Keycloak
    r = b.go("POST", KAYA + "/connect")
    on_kc = "/realms/" in r.final_url  # type: ignore[attr-defined]
    check("Kaya's connect lands on Keycloak's sign-in page", on_kc and 'name="username"' in r.text, r.final_url)  # type: ignore[attr-defined]
    r = b.keycloak_login_if_asked(r)
    check("Keycloak hands Thandi to Valet's consent screen", "/handoff/consent" in r.final_url,  # type: ignore[attr-defined]
          r.final_url.split("?")[0])  # type: ignore[attr-defined]
    r = b.submit(r, lambda f: "/handoff/decision" in f["action"], button=("decision", "allow"), level="bill_payer",
                 monthly="200000")
    r = b.submit(r, lambda f: "valet_result" in f["fields"])          # the auto-POST back into the Keycloak login
    msg = kaya_last(b)
    check("Kaya connected via Keycloak as Bill payer, no password seen", "Connected" in msg and "Bill payer" in msg, msg)

    # 2. Pay within the limit
    b.go("POST", KAYA + "/do/water")
    msg = kaya_last(b)
    check("Payment within the limit goes through (R640)", msg.startswith("Paid"), msg)

    # 3. New recipient is held for approval
    b.go("POST", KAYA + "/do/power")
    msg = kaya_last(b)
    check("New recipient is held for approval in the bank app", "approve" in msg, msg)

    # 4. Approve in the bank app (bank signs in through Keycloak; approval may force a fresh Keycloak sign-in)
    r = b.keycloak_login_if_asked(b.go("GET", BANK + "/app/approvals"))
    ids = re.findall(r'/app/approvals/([A-Za-z0-9_\-]+)"', r.text)
    if check("Approval shows up in the bank app", bool(ids), f"{len(ids)} pending"):
        r = b.keycloak_login_if_asked(b.go("GET", f"{BANK}/app/approvals/{ids[0]}"))
        r = b.submit(r, lambda f: "/app/approvals/" in f["action"], button=("decision", "approve"))
        r = b.keycloak_login_if_asked(r)
        if "/app/approvals/" in r.final_url and "decision" in r.text:   # step-up happened after the click: click again
            r = b.submit(r, lambda f: "/app/approvals/" in f["action"], button=("decision", "approve"))
        b.go("GET", KAYA + "/approval")
        msg = kaya_last(b)
        check("Approved payment is made exactly once", "once" in msg, msg)

    # 5. Beneficiary add is refused
    b.go("POST", KAYA + "/do/beneficiary")
    msg = kaya_last(b)
    check("Adding a beneficiary is refused", "said no" in msg, msg)

    # 6. Pause from the bank app stops a still-valid Keycloak token
    r = b.keycloak_login_if_asked(b.go("GET", BANK + "/app"))
    gids = re.findall(r'/app/agents/([A-Za-z0-9_\-]+)"', r.text)
    if check("Kaya is listed under the customer's AI agents", bool(gids)):
        gid = gids[0]
        r = b.go("GET", f"{BANK}/app/agents/{gid}")
        b.submit(r, lambda f: f["action"].endswith("/pause"))
        b.go("POST", KAYA + "/do/balance")
        msg = kaya_last(b)
        check("Pause stops Kaya on its very next call", "said no" in msg, msg)
        r = b.go("GET", f"{BANK}/app/agents/{gid}")
        b.submit(r, lambda f: f["action"].endswith("/resume"))
        b.go("POST", KAYA + "/do/balance")
        check("Resume restores access", kaya_last(b).startswith("Your balances"), kaya_last(b))

    # 7. Consent Service: a third-party app, Open Banking style, through the same Keycloak
    consent_service(b)

    # 8. A real AI assistant's connector (Claude) through the bank's MCP gateway
    mcp_gateway(b)

    # 9. Receipts
    v = b.go("GET", BANK + "/receipts/verify").json()
    check("Receipt chain verifies (tamper-evident)", bool(v.get("ok", v.get("valid"))), str(v)[:120])

    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{GREEN + 'READY' if not failed else RED + 'NOT READY'}{END}: {len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
