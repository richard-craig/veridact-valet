"""
The customer's side, inside the bank: sign in, the consent screen (rendered by authz.py),
the AI agents dashboard, per-agent activity with receipts, and approvals.

In production these screens live in the bank's own app. Sign-in belongs to the bank's identity provider:
set CUSTOMER_IDP=oidc to use any OpenID Connect provider (idp.py). Without it the PoC uses a demo password,
so it runs anywhere.
"""
from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from itsdangerous import BadSignature, URLSafeTimedSerializer
from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..common.money import rand, to_cents
from . import levels as L
from .config import SAST
from .idp import SignInError

COOKIE = "marula_session"
OIDC_COOKIE = "marula_oidc"
_env = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"), autoescape=select_autoescape())


def _ser(bank) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(bank.cfg.session_secret, salt="marula")


def current_customer(bank, request: Request) -> dict[str, Any] | None:
    raw = request.cookies.get(COOKIE)
    if not raw:
        return None
    try:
        data = _ser(bank).loads(raw, max_age=8 * 3600)
        cid = data["cid"]
    except (BadSignature, KeyError, TypeError):
        return None
    row = bank.store.one("SELECT id, username, name FROM customers WHERE id=?", cid)
    return {**dict(row), "auth_at": data.get("at", 0), "via": data.get("via", "local")} if row else None


def set_session(bank, resp, cid: str, via: str) -> None:
    resp.set_cookie(COOKIE, _ser(bank).dumps({"cid": cid, "at": int(time.time()), "via": via}), httponly=True,
                    samesite="lax")


def needs_step_up(bank, cus: dict[str, Any]) -> bool:
    """Consent and approvals need a recent sign-in; the bank's IdP decides what 'sign in' means."""
    return time.time() - cus.get("auth_at", 0) > bank.cfg.step_up_max_age


def step_up(next_url: str) -> RedirectResponse:
    return RedirectResponse("/login?" + urlencode({"next": next_url, "step_up": "1"}), 303)


def safe_next(nxt: str) -> str:
    return nxt if nxt.startswith("/") and not nxt.startswith("//") and not urlparse(nxt).netloc else "/app"


def csrf_token(bank, cid: str) -> str:
    return _ser(bank).dumps({"csrf": cid})


def csrf_ok(bank, cid: str, token: str) -> bool:
    try:
        return _ser(bank).loads(token, max_age=3600).get("csrf") == cid
    except (BadSignature, AttributeError):
        return False


def render(request: Request, template: str, bank, status: int = 200, **ctx: Any) -> HTMLResponse:
    html = _env.get_template(template).render(bank_name=bank.cfg.bank_name, request=request, **ctx)
    return HTMLResponse(html, status_code=status)


def describe(rec: dict[str, Any]) -> dict[str, str]:
    """Turn a receipt into a line a customer understands."""
    a, o, b = rec.get("action"), rec.get("outcome"), rec.get("basis")
    d = rec.get("detail") or {}
    amt = f" · {rand(to_cents(d['amount']))}" if d.get("amount") else ""
    to = d.get("to", "")
    if a == "connect":
        return {"title": "Connected", "sub": d.get("summary", ""), "kind": "info"}
    if a == "payment" and o == "allowed":
        return {"title": f"Paid {to}{amt}", "sub": "Approved by you" if b == "approval" else "Within your limit",
                "kind": "approved" if b == "approval" else "ok"}
    if a == "payment" and o == "held":
        return {"title": f"Asked before paying {to}{amt}", "sub": rec.get("reason", ""), "kind": "held"}
    if a == "approval_request":
        return {"title": f"Asked you to approve {to}{amt}", "sub": "Sent to your Marula app", "kind": "held"}
    if a == "approval_decision":
        return {"title": f"You {rec.get('outcome')} {to}{amt}", "sub": "In your Marula app", "kind": "info"}
    if a == "reconfirm":
        return {"title": "Kept by you", "sub": "Reviewed after signing in again", "kind": "info"}
    if a in ("pause", "resume", "revoke", "pause_all"):
        words = {"pause": "Paused", "resume": "Resumed", "revoke": "Disconnected", "pause_all": "Paused (pause all)"}
        return {"title": f"{words[a]} by you", "sub": (rec.get("reason") or "").capitalize(), "kind": "info"}
    if a == "read_balances" and o == "allowed":
        return {"title": "Checked balances", "sub": "Within your limit", "kind": "ok"}
    if a == "read_transactions" and o == "allowed":
        return {"title": "Read transactions", "sub": "Within your limit", "kind": "ok"}
    if a == "add_beneficiary":
        return {"title": f"Blocked: tried to add beneficiary “{d.get('name', '')}”", "sub": "Not allowed · nothing changed",
                "kind": "blocked"}
    return {"title": f"Blocked: {a}{(' to ' + to) if to else ''}{amt}", "sub": rec.get("reason", ""), "kind": "blocked"}


def router(bank) -> APIRouter:
    r = APIRouter()
    store = bank.store

    def need_login(request: Request):
        cus = current_customer(bank, request)
        if not cus:
            return None, RedirectResponse("/login?next=" + request.url.path, 303)
        return cus, None

    def owned_grant(cus, gid: str) -> dict[str, Any] | None:
        g = store.grant(gid)
        return g if g and g["customer"] == cus["id"] else None

    def grant_view(g: dict[str, Any]) -> dict[str, Any]:
        rec = bank.registry.lookup(g["client_id"])
        limit = L.monthly_limit(g["details"])
        recs = bank.receipts.for_grant(g["id"])
        last = next((x for x in recs if x["action"] not in ("connect", "reconfirm")), recs[-1] if recs else None)
        confirmed = datetime.fromtimestamp(g.get("confirmed_at") or g["created"], SAST)
        pend = store.q("SELECT id FROM approvals WHERE grant_id=? AND status='pending' AND expires>?", g["id"], time.time())
        return {**g, "agent": rec, "level_title": L.LEVELS[g["level"]]["title"],
                "spent": rand(store.spent(g["id"])), "limit": rand(limit) if limit else None,
                "pct": min(100, round(100 * store.spent(g["id"]) / limit)) if limit else 0,
                "days_left": max(0, int((g["expires"] - time.time()) // 86400)),
                "last": describe(last) if last else None, "pending": len(pend),
                "confirmed": f"{confirmed.day} {confirmed:%B %Y}",
                "trusted": bank.registry.is_trusted(g["client_id"])}

    @r.get("/")
    def home():
        return RedirectResponse("/app", 303)

    @r.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request, next: str = "/app", step_up: str = ""):
        nxt, fresh = safe_next(next), step_up == "1"
        if bank.signin:                              # the bank's IdP signs the customer in
            url, kept = await bank.signin.start(step_up=fresh)
            resp = RedirectResponse(url, 303)
            resp.set_cookie(OIDC_COOKIE, _ser(bank).dumps({**kept, "next": nxt}), httponly=True, samesite="lax",
                            max_age=600)
            return resp
        return render(request, "login.html", bank, next=nxt, step_up=fresh, error=None)

    @r.post("/login")
    async def login(request: Request):
        if bank.signin:
            return RedirectResponse("/login", 303)
        form = await request.form()
        nxt = safe_next(str(form.get("next") or "/app"))
        cus = store.check_password(str(form.get("username", "")), str(form.get("password", "")))
        if not cus:
            return render(request, "login.html", bank, status=401, next=nxt, step_up=False,
                          error="That username and password don't match.")
        resp = RedirectResponse(nxt, 303)
        set_session(bank, resp, cus["id"], "local")
        return resp

    @r.get("/login/callback", response_class=HTMLResponse)
    async def login_callback(request: Request, code: str = "", state: str = "", error: str = ""):
        if not bank.signin:
            return HTMLResponse("Not found", status_code=404)
        try:
            kept = _ser(bank).loads(request.cookies.get(OIDC_COOKIE, ""), max_age=600)
        except BadSignature:
            kept = {}
        try:
            if error:
                raise SignInError("Sign-in was cancelled." if error == "access_denied" else f"Sign-in failed ({error}).")
            claims = await bank.signin.finish(code, state, kept)
            cus = store.customer_for_idp(bank.signin.customer_value(claims))
            if not cus:
                raise SignInError("You signed in, but no Marula Bank customer matches that identity.")
        except SignInError as e:
            resp = render(request, "signin_error.html", bank, status=403, error=str(e))
            resp.delete_cookie(OIDC_COOKIE)
            return resp
        resp = RedirectResponse(safe_next(kept.get("next", "/app")), 303)
        resp.delete_cookie(OIDC_COOKIE)
        set_session(bank, resp, cus["id"], "oidc")
        return resp

    @r.post("/logout")
    def logout():
        resp = RedirectResponse("/login", 303)
        resp.delete_cookie(COOKIE)
        return resp

    @r.get("/app", response_class=HTMLResponse)
    def dashboard(request: Request):
        cus, redirect = need_login(request)
        if redirect:
            return redirect
        grants = [grant_view(g) for g in store.grants_for(cus["id"]) if g["status"] != "revoked"]
        pending = sum(g["pending"] for g in grants)
        return render(request, "dashboard.html", bank, customer=cus, grants=grants, pending=pending,
                      csrf=csrf_token(bank, cus["id"]))

    @r.get("/app/agents/{gid}", response_class=HTMLResponse)
    def agent_page(request: Request, gid: str):
        cus, redirect = need_login(request)
        if redirect:
            return redirect
        g = owned_grant(cus, gid)
        if not g:
            return HTMLResponse("Not found", status_code=404)
        acct = store.one("SELECT * FROM accounts WHERE id=?", L.find(g["details"], "valet_accounts")["accounts"][0])
        summary = L.plain_summary(g["level"], g["details"], f"{acct['name']} {acct['number']}", bank.cfg.max_grant_days)
        items = [{**describe(x), "time": x["time"][11:16], "date": x["time"][:10], "hash": x["hash"][:19]}
                 for x in bank.receipts.for_grant(gid)]
        return render(request, "agent.html", bank, customer=cus, g=grant_view(g), summary=summary, items=items,
                      csrf=csrf_token(bank, cus["id"]))

    @r.post("/app/agents/{gid}/{action}")
    async def agent_action(request: Request, gid: str, action: str):
        cus, redirect = need_login(request)
        if redirect:
            return redirect
        form = await request.form()
        g = owned_grant(cus, gid)
        if not g or not csrf_ok(bank, cus["id"], str(form.get("csrf", ""))) or action not in ("pause", "resume", "revoke"):
            return HTMLResponse("Not allowed", status_code=403)
        if g["status"] in ("revoked", "expired"):
            return RedirectResponse("/app", 303)
        store.set_status(gid, {"pause": "paused", "resume": "active", "revoke": "revoked"}[action])
        bank.receipts.append(grant_id=gid, agent=g["client_id"], customer=cus["id"], action=action, outcome="done",
                             basis="customer")
        return RedirectResponse("/app" if action == "revoke" else f"/app/agents/{gid}", 303)

    @r.post("/app/pause-all")
    async def pause_all(request: Request):
        cus, redirect = need_login(request)
        if redirect:
            return redirect
        form = await request.form()
        if not csrf_ok(bank, cus["id"], str(form.get("csrf", ""))):
            return HTMLResponse("Not allowed", status_code=403)
        for g in store.grants_for(cus["id"]):
            if g["status"] == "active":
                store.set_status(g["id"], "paused")
                bank.receipts.append(grant_id=g["id"], agent=g["client_id"], customer=cus["id"], action="pause_all",
                                     outcome="done", basis="customer")
        return RedirectResponse("/app", 303)

    # ------------------------------------------------------------ approvals
    def approval_view(row) -> dict[str, Any]:
        d = json.loads(row["detail"])
        g = store.grant(row["grant_id"])
        acct = store.one("SELECT * FROM accounts WHERE id=?", d["from"])
        is_new = not store.one("SELECT 1 FROM beneficiaries WHERE customer=? AND account=?", g["customer"], d["to"]["account"])
        return {"id": row["id"], "grant_id": row["grant_id"], "agent": bank.registry.lookup(row["client_id"]),
                "amount": rand(to_cents(d["amount"]["amount"])), "to": d["to"]["name"], "to_account": d["to"]["account"],
                "from": f"{acct['name']} {acct['number']}", "reference": d.get("reference", ""), "new": is_new,
                "reason": row["reason"], "message": row["message"], "status": row["status"],
                "seconds_left": max(0, int(row["expires"] - time.time()))}

    @r.get("/app/approvals", response_class=HTMLResponse)
    def approvals(request: Request):
        cus, redirect = need_login(request)
        if redirect:
            return redirect
        rows = store.q("""SELECT a.* FROM approvals a JOIN grants g ON g.id=a.grant_id
                          WHERE g.customer=? AND a.status='pending' AND a.expires>? ORDER BY a.created DESC""",
                       cus["id"], time.time())
        return render(request, "approvals.html", bank, customer=cus, items=[approval_view(x) for x in rows])

    @r.get("/app/approvals/{aid}", response_class=HTMLResponse)
    def approval(request: Request, aid: str):
        cus, redirect = need_login(request)
        if redirect:
            return redirect
        row = store.one("SELECT * FROM approvals WHERE id=?", aid)
        if not row or not owned_grant(cus, row["grant_id"]):
            return HTMLResponse("Not found", status_code=404)
        if row["status"] == "pending" and needs_step_up(bank, cus):
            return step_up(f"/app/approvals/{aid}")
        return render(request, "approval.html", bank, customer=cus, a=approval_view(row), csrf=csrf_token(bank, cus["id"]))

    @r.post("/app/approvals/{aid}")
    async def decide(request: Request, aid: str):
        cus, redirect = need_login(request)
        if redirect:
            return redirect
        form = await request.form()
        row = store.one("SELECT * FROM approvals WHERE id=?", aid)
        if not row or not owned_grant(cus, row["grant_id"]) or not csrf_ok(bank, cus["id"], str(form.get("csrf", ""))):
            return HTMLResponse("Not allowed", status_code=403)
        if row["status"] != "pending" or row["expires"] < time.time():
            return RedirectResponse(f"/app/approvals/{aid}", 303)
        if needs_step_up(bank, cus):
            return step_up(f"/app/approvals/{aid}")
        decision = "approved" if form.get("decision") == "approve" else "denied"
        store.x("UPDATE approvals SET status=? WHERE id=?", decision, aid)
        d = json.loads(row["detail"])
        bank.receipts.append(grant_id=row["grant_id"], agent=row["client_id"], customer=cus["id"], action="approval_decision",
                             outcome=decision, basis="customer", approval=aid,
                             detail={"to": d["to"]["name"], "amount": d["amount"]["amount"], "currency": "ZAR"})
        return RedirectResponse(f"/app/agents/{row['grant_id']}", 303)

    # ------------------------------------------- bank operations (demo only)
    @r.get("/ops", response_class=HTMLResponse)
    def ops(request: Request):
        trust_file = bank.cfg.data_dir / "trust.json"
        agents = json.loads(trust_file.read_text()) if trust_file.exists() else {}
        rows = [{"client_id": k, **v, "trusted": bank.registry.is_trusted(k)} for k, v in agents.items()]
        return render(request, "ops.html", bank, agents=rows, chain=bank.receipts.verify_chain())

    @r.post("/ops/agents/{client_id}/trust")
    async def set_trust(request: Request, client_id: str):
        form = await request.form()
        bank.registry.set_trust(client_id, form.get("trusted") == "1")
        return RedirectResponse("/ops", 303)

    @r.get("/receipts/verify")
    def verify_receipts():
        return JSONResponse(bank.receipts.verify_chain())

    return r
