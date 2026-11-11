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

import os
import re
import sys
import time
from html.parser import HTMLParser
from http.cookiejar import CookieJar, DefaultCookiePolicy
from urllib.parse import urljoin, urlsplit

import httpx

HOST = os.environ.get("DEMO_HOST", "localhost")
SCHEME = os.environ.get("DEMO_SCHEME", "http")
KAYA = os.environ.get("KAYA_URL", f"{SCHEME}://{HOST}:8001")
BANK = os.environ.get("BANK_URL", f"{SCHEME}://{HOST}:8000")
ACME = os.environ.get("ACME_URL", f"{SCHEME}://{HOST}:8002")
USER, PASSWORD = os.environ.get("DEMO_USER", "thandi"), os.environ.get("DEMO_PASSWORD", "demo")

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

    def go(self, method: str, url: str, data: dict | None = None) -> httpx.Response:
        for _ in range(15):
            r = self.c.request(method, url, data=data)
            if r.status_code in (301, 302, 303, 307):
                url, method, data = urljoin(url, r.headers["location"]), ("GET" if r.status_code != 307 else method), \
                    (None if r.status_code != 307 else data)
                continue
            r.final_url = url  # type: ignore[attr-defined]
            return r
        raise RuntimeError("too many redirects")

    def submit(self, r: httpx.Response, pick=lambda f: True, button: tuple[str, str] | None = None, **values) -> httpx.Response:
        fs = [f for f in forms(r.text) if pick(f)]
        if not fs:
            raise RuntimeError(f"no matching form on {r.final_url}")  # type: ignore[attr-defined]
        f = fs[0]
        data = {**f["fields"], **values}
        if button:
            data[button[0]] = button[1]
        return self.go(f["method"].upper(), urljoin(r.final_url, f["action"]), data)  # type: ignore[attr-defined]

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

    # 8. Receipts
    v = b.go("GET", BANK + "/receipts/verify").json()
    check("Receipt chain verifies (tamper-evident)", bool(v.get("ok", v.get("valid"))), str(v)[:120])

    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{GREEN + 'READY' if not failed else RED + 'NOT READY'}{END}: {len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
