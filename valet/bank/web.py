"""
The customer's side, inside the bank: sign in, the consent screen (rendered by authz.py),
the AI agents dashboard, per-agent activity with receipts, and approvals.

In production these screens live in the bank's own app. Sign-in belongs to the bank's identity provider:
set CUSTOMER_IDP=oidc to use any OpenID Connect provider (idp.py). Without it the PoC uses a demo password,
so it runs anywhere.
"""
from __future__ import annotations

import json
import os
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
from . import evidence
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


_CONNECTOR_READS = {"list_accounts": "Listed your accounts", "get_balance": "Checked a balance",
                    "list_transactions": "Read transactions", "list_payees": "Listed your saved beneficiaries",
                    "get_payment_status": "Checked on a payment"}
_CONNECTOR_REFUSALS = {
    "PAYEE_NOT_IN_MANDATE": ("Blocked: tried to pay someone who is not a saved beneficiary", "Nothing was paid"),
    "MONTHLY_LIMIT_EXCEEDED": ("Blocked: over your monthly limit", "Nothing was paid"),
    "ACCOUNT_NOT_IN_MANDATE": ("Blocked: an account you did not share", "Nothing was shared or paid"),
    "TOOL_NOT_IN_MANDATE": ("Blocked: not allowed by your settings", "Nothing changed"),
    "TOO_MANY_PENDING": ("Blocked: too many payments already waiting for you", "Nothing was paid"),
    "MANDATE_PAUSED": ("Blocked while paused", "Nothing was shared or paid"),
    "MANDATE_REVOKED": ("Blocked after you disconnected", "Nothing was shared or paid"),
    "MANDATE_EXPIRED": ("Blocked: this connection has expired", "Nothing was shared or paid"),
    "AGENT_UNTRUSTED": ("Blocked: the bank no longer trusts this assistant", "Nothing was shared or paid"),
}


def _describe_connector(tool: str, outcome: str, to: str, amt: str, rec: dict[str, Any]) -> dict[str, str]:
    """A line for something an assistant did through the MCP gateway (Claude and similar)."""
    if outcome == "allowed":
        return {"title": _CONNECTOR_READS.get(tool, "Read information"), "sub": "Allowed by your settings", "kind": "ok"}
    if outcome == "held":
        return {"title": f"Asked you to approve {to}{amt}", "sub": "Sent to your Marula app", "kind": "held"}
    code = (rec.get("reason_codes") or [""])[0]
    title, sub_ = _CONNECTOR_REFUSALS.get(code, ("Blocked: a request outside your settings", "Nothing changed"))
    return {"title": title + (amt if tool == "pay_existing_payee" else ""), "sub": sub_, "kind": "blocked"}


def stop_note(action: str, payments: dict[str, int]) -> str:
    """What pausing or disconnecting did to payments in flight, in the customer's words."""
    if action == "resume":
        return "Payments you approved before the pause were cancelled; the assistant must ask again"
    n, done, cancelled = payments.get("with_bank", 0), payments.get("already_paid", 0), payments.get("cancelled", 0)
    parts = []
    if n:
        parts.append(f"{'One payment was' if n == 1 else f'{n} payments were'} already with the bank and may still complete")
    if done:
        parts.append(f"{'One payment had' if done == 1 else f'{done} payments had'} already been made")
    if cancelled:
        parts.append(f"{'One payment' if cancelled == 1 else f'{cancelled} payments'} not yet made "
                     f"{'was' if cancelled == 1 else 'were'} cancelled")
    return "; ".join(parts)


def when(value: Any) -> str:
    """A receipt time (ISO text) or a stored timestamp, as the customer reads it: 16 Nov 2026, 10:42."""
    t = datetime.fromisoformat(value) if isinstance(value, str) else datetime.fromtimestamp(value, SAST)
    return f"{t.day} {t.strftime('%b %Y, %H:%M')}"


def describe(rec: dict[str, Any]) -> dict[str, str]:
    """Turn a receipt into a line a customer understands."""
    a, o, b = rec.get("action"), rec.get("outcome"), rec.get("basis")
    d = rec.get("detail") or {}
    try:
        amt = f" · {rand(to_cents(d['amount']))}" if d.get("amount") else ""
    except ValueError:
        amt = ""
    to = d.get("to", "")
    if str(a).startswith("mcp:"):
        return _describe_connector(str(a)[4:], o, to, amt, rec)
    if a == "connect":
        return {"title": "Connected", "sub": d.get("summary", ""), "kind": "info"}
    if a == "payment" and o == "allowed":
        return {"title": f"Paid {to}{amt}", "sub": "Approved by you" if b == "approval" else "Within your limit",
                "kind": "approved" if b == "approval" else "ok"}
    if a == "payment" and o == "unknown":
        return {"title": f"Waiting for the bank to confirm {to}{amt}", "sub": "Held against your limit until confirmed",
                "kind": "held"}
    if a == "payment" and o == "failed":
        words = {"insufficient_funds": "Not enough money in the account"}
        return {"title": f"Not paid: {to}{amt}", "sub": words.get(rec.get("reason", ""), "Declined by the bank"),
                "kind": "blocked"}
    if a == "refresh" and o == "retried":
        return {"title": "Assistant reconnected after a lost reply", "sub": "Same key; nothing changed", "kind": "info"}
    if a == "payment" and o == "cancelled":
        return {"title": f"Cancelled: {to}{amt}", "sub": "Stopped before the bank accepted it · nothing was paid",
                "kind": "blocked"}
    if a == "payment" and o == "escalated":
        return {"title": f"Still waiting for the bank: {to}{amt}", "sub": "Passed to the bank's operations team · "
                "held against your limit", "kind": "held"}
    if a == "key_binding":
        return {"title": "Linked to the assistant's key", "sub": "On its first call", "kind": "info"}
    if a == "payment" and o == "held":
        return {"title": f"Asked before paying {to}{amt}", "sub": rec.get("reason", ""), "kind": "held"}
    if a == "approval_request":
        return {"title": f"Asked you to approve {to}{amt}", "sub": "Sent to your Marula app", "kind": "held"}
    if a == "approval_decision":
        return {"title": f"You {rec.get('outcome')} {to}{amt}", "sub": "In your Marula app", "kind": "info"}
    if a in ("pause", "resume", "revoke", "pause_all"):
        words = {"pause": "Paused", "resume": "Resumed", "revoke": "Disconnected", "pause_all": "Paused (pause all)"}
        return {"title": f"{words[a]} by you", "sub": stop_note(a, rec.get("payments") or {}), "kind": "info"}
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

    def payee_names(g: dict[str, Any]) -> list[str] | None:
        ids = L.payees(g["details"])
        if not ids:
            return None
        names = {r["id"]: r["name"] for r in store.q("SELECT id, name FROM beneficiaries WHERE customer=?", g["customer"])}
        return [names.get(i, i) for i in ids]

    def owned_grant(cus, gid: str) -> dict[str, Any] | None:
        g = store.grant(gid)
        return g if g and g["customer"] == cus["id"] else None

    def grant_view(g: dict[str, Any]) -> dict[str, Any]:
        rec = bank.registry.lookup(g["client_id"])
        limit = L.monthly_limit(g["details"])
        recs = bank.receipts.for_grant(g["id"])
        last = next((x for x in recs if x["action"] not in ("connect",)), recs[-1] if recs else None)
        pend = store.q("SELECT id FROM approvals WHERE grant_id=? AND status='pending' AND expires>?", g["id"], time.time())
        return {**g, "agent": rec, "level_title": L.LEVELS[g["level"]]["title"],
                "spent": rand(store.spent(g["id"])), "limit": rand(limit) if limit else None,
                "pct": min(100, round(100 * store.spent(g["id"]) / limit)) if limit else 0,
                "days_left": max(0, int((g["expires"] - time.time()) // 86400)),
                "last": describe(last) if last else None, "pending": len(pend),
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
        summary = L.plain_summary(g["level"], g["details"], f"{acct['name']} {acct['number']}", bank.cfg.max_grant_days,
                                  payee_names=payee_names(g))
        # A line about a payment opens its evidence page: every record the bank holds for that one payment.
        held_for = {i["approval"]: i["id"] for i in bank.payments.for_grant(gid) if i["approval"]}
        items = [{**describe(x), "time": x["time"][11:16], "date": x["time"][:10], "hash": x["hash"][:19],
                  "payment": x.get("payment_intent") or held_for.get(x.get("approval"))}
                 for x in bank.receipts.for_grant(gid)]
        return render(request, "agent.html", bank, customer=cus, g=grant_view(g), summary=summary, items=items,
                      csrf=csrf_token(bank, cus["id"]))

    @r.get("/app/agents/{gid}/payments/{intent_id}", response_class=HTMLResponse)
    def payment_evidence(request: Request, gid: str, intent_id: str):
        """Everything the bank holds about one payment an agent asked for, on one page, in plain language:
        who asked, under what authority, whose decision it was, and what the bank did (design section 8.1)."""
        cus, redirect = need_login(request)
        if redirect:
            return redirect
        g = owned_grant(cus, gid)
        intent = bank.payments.get(intent_id) if g else None
        if not g or not intent or intent["grant_id"] != gid:
            return HTMLResponse("Not found", status_code=404)
        d, agent = intent["detail"], bank.registry.lookup(g["client_id"])
        acct = store.one("SELECT * FROM accounts WHERE id=?", d["from"])
        shared = store.one("SELECT * FROM accounts WHERE id=?", L.find(g["details"], "valet_accounts")["accounts"][0])
        records = list(reversed(bank.receipts.for_grant(gid)))                        # oldest first
        mine = [x for x in records if x.get("payment_intent") == intent_id
                or (intent["approval"] and x.get("approval") == intent["approval"])]
        connect = next((x for x in records if x["action"] == "connect"), None)
        ap = store.one("SELECT * FROM approvals WHERE id=?", intent["approval"] or "")
        decided = next((x for x in mine if x["action"] == "approval_decision"), None)
        asked = next((x for x in mine if x.get("agent_supplied_instruction")), None)

        state = intent["status"]
        to, amount = d["to"]["name"], rand(intent["amount"])
        headline = {"confirmed": f"Paid {to}", "failed": f"Not paid: {to}", "approval_required": f"Not paid: {to}",
                    }.get(state, f"Waiting for the bank to confirm {to}")
        if state == "confirmed" and intent["basis"] == "approval":
            decision = {"title": "You approved this exact payment", "kind": "approved",
                        "text": (f"You approved it in the {bank.cfg.bank_name} app on {when(decided['time'])}, after "
                                 "signing in again. " if decided else "You approved it through the bank's own approval step. ")
                                + "The approval covered this one payment only."}
        elif intent["basis"] == "grant" and state != "approval_required":
            decision = {"title": "Inside your standing limit", "kind": "ok",
                        "text": "This payment was to a saved beneficiary and inside the monthly limit you set, so the "
                                "bank did not ask you to approve it."}
        else:
            words = {"denied": "You declined this payment.", "approved": "You approved this exact payment.",
                     "pending": "Waiting for your decision.", "cancelled": "The request was cancelled.",
                     "expired": "The request ran out before you answered."}
            status = ap["status"] if ap else None
            if status == "pending" and ap["expires"] < time.time():
                status = "expired"
            decision = {"title": "Sent to you for approval", "kind": "held",
                        "text": words.get(status, "The agent has not asked you to approve it yet.")}
        did = {"confirmed": "Paid once, by the bank's own payment system.",
               "failed": {"insufficient_funds": "Not paid: there was not enough money in the account.",
                          "not_received_by_the_bank": "Not paid: the instruction never reached the payment system."
                          }.get(intent["reason"] or "", "Not paid: the bank's payment system declined it."),
               "approval_required": "Nothing was paid. The bank held the payment and asked you first.",
               }.get(state, "The bank's payment system has not confirmed this payment yet. The amount is held "
                            "against your limit until it does.")
        day = mine[0]["time"][:10] if mine else None
        nearby = [x for x in records if x not in mine and x["time"][:10] == day
                  and x.get("outcome") in ("refused", "held") and x.get("action") not in ("approval_request",)]
        chain = bank.receipts.verify_chain()
        view = {
            "id": intent_id, "headline": headline, "amount": amount, "state": state,
            "paid": state == "confirmed", "to": to, "to_account": d["to"]["account"],
            "from": f"{acct['name']} {acct['number']}" if acct else d["from"], "reference": d.get("reference", ""),
            "asked_at": when(intent["created"]), "settled_at": when(intent["updated"]) if state in ("confirmed", "failed") else None,
            "channel": ("Through an AI assistant connector. The bank knows the assistant platform, not an individual agent."
                        if intent["channel"] == "mcp_gateway" else
                        "Directly, with every request signed by the agent's own key."),
            "key": (g["jkt"] or "")[:16], "connected_at": when(connect["time"]) if connect else None,
            "mandate": L.plain_summary(g["level"], g["details"], f"{shared['name']} {shared['number']}", bank.cfg.max_grant_days,
                                       payee_names=payee_names(g)),
            "consent_hash": (g["consent_hash"] or "")[:26],
            "decision": decision, "why": ap["reason"] if ap else intent["reason"], "note": ap["message"] if ap else None,
            "instruction": asked.get("agent_supplied_instruction") if asked else None,
            "did": did, "bank_payment_id": intent["bank_payment_id"], "request_ref": intent["idem_key"],
            "evidence": {"standing_mandate": "Standing mandate: the record shows the payment was within what you allowed.",
                         "customer_confirmed": "Customer confirmed: the record shows you approved this exact payment."
                         }["customer_confirmed" if intent["basis"] == "approval" and state == "confirmed" else "standing_mandate"]
                        if state == "confirmed" else None,
            "timeline": [{**describe(x), "when": when(x["time"]), "hash": x["hash"][:19]} for x in mine],
            "nearby": [{**describe(x), "when": when(x["time"])} for x in nearby[:5]],
            "chain_ok": chain["ok"], "records": len(mine),
        }
        return render(request, "payment_evidence.html", bank, customer=cus, g=grant_view(g), agent=agent, p=view)

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
        stopped = bank.stop_grant(gid, {"pause": "paused", "resume": "active", "revoke": "revoked"}[action],
                                  {"pause": "the customer paused the agent", "revoke": "the customer disconnected the agent",
                                   "resume": ""}[action])
        bank.receipts.append(grant_id=gid, agent=g["client_id"], customer=cus["id"], action=action, outcome="done",
                             basis="customer", payments=stopped)
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
                stopped = bank.stop_grant(g["id"], "paused", "the customer paused all agents")
                bank.receipts.append(grant_id=g["id"], agent=g["client_id"], customer=cus["id"], action="pause_all",
                                     outcome="done", basis="customer", payments=stopped)
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
        known = bank.known_assistants
        assistants = [{"client_id": c, **bank.assistant(c)} for c in (known.entries if known else {})]
        svc = getattr(bank, "decision_service", None)
        decisions = [decision_line(e) for e in list(svc.log)[:15]] if svc else []
        return render(request, "ops.html", bank, agents=rows, chain=bank.receipts.verify_chain(),
                      assistants=assistants, decisions=decisions,
                      transport=getattr(bank.decisions, "transport", "in-process"),
                      attester_admin=os.environ.get("VERIDACT_ADMIN_URL", ""))

    def decision_line(e: dict[str, Any]) -> dict[str, Any]:
        """One decision the bank's MCP server asked for, as the operations page shows it."""
        req, out = e["request"], e["response"]
        if e["call"] == "evaluation":
            ctx = out.get("context") or {}
            what = (req.get("action") or {}).get("name", "")
            if req.get("context", {}).get("approval"):
                what += " (after approval)"
            verdict = ("permit · " + ctx.get("valet", {}).get("outcome", "")) if out.get("decision") else \
                ("deny · " + str(ctx.get("reason", "")))
        elif e["call"] == "evaluations":
            what = f"tools/list ({len(req.get('evaluations') or [])} tools)"
            verdict = f"{sum(1 for x in out.get('evaluations', []) if x.get('decision'))} visible"
        else:
            what = e["call"] + " " + str(req.get("reservation", ""))[:14]
            verdict = str(out.get("state") or out.get("status") or "")
        return {"at": e["at"], "call": e["call"], "what": what, "verdict": verdict,
                "json": json.dumps({"request": req, "response": out}, indent=1)[:2400]}

    @r.post("/ops/agents/{client_id}/trust")
    async def set_trust(request: Request, client_id: str):
        form = await request.form()
        bank.registry.set_trust(client_id, form.get("trusted") == "1")
        return RedirectResponse("/ops", 303)

    @r.get("/ops/payments/escalated")
    def escalated_payments():
        """The operations queue `payments-unknown-outcome`: payments the bank has neither settled nor tombstoned.
        Each is still held against the customer's limit. The bank sets the SLA for working this queue."""
        return JSONResponse({"queue": "payments-unknown-outcome", "items": bank.payments.escalated()})

    @r.post("/ops/denylist")
    async def add_to_denylist(request: Request):
        """The bank stops an agent, an operator or a key at once, on every node, without waiting for the registry."""
        body = await request.json()
        try:
            out = bank.deny(str(body.get("kind", "")), str(body.get("value", "")), str(body.get("reason", ""))[:200],
                            by=str(body.get("by") or "bank operations")[:100])
        except ValueError:
            return JSONResponse({"error": "invalid_request",
                                 "error_description": "kind must be client_id, operator or jkt, and value is required"},
                                status_code=400)
        return JSONResponse(out)

    @r.delete("/ops/denylist/{kind}/{value}")
    def remove_from_denylist(kind: str, value: str):
        return JSONResponse(bank.undeny(kind, value))

    @r.get("/ops/evidence")
    def evidence_pack(grant_id: str = "", client_id: str = "", reason: str = ""):
        """An evidence pack for one grant or one agent: receipts with signatures, the policies they name, payment
        intents, denylist entries and the signed chain head, checkable offline (design section 8.3)."""
        try:
            return JSONResponse(evidence.build(bank, grant_id=grant_id or None, client_id=client_id or None,
                                               reason=reason))
        except evidence.EvidenceNotFound as e:
            # Fixed messages only: never echo exception text to the caller.
            messages = {"scope_required": "name a grant_id or a client_id",
                        "no_matching_grant": "no grant matches"}
            return JSONResponse({"error": e.code, "error_description": messages.get(e.code, "not found")},
                                status_code=404)

    @r.get("/ops/policies")
    def policies():
        """The policy in force and every policy this deployment has run with (design section 8.2)."""
        return JSONResponse({"current": {**bank.policy.ref, "labelled": bank.policy.labelled,
                                         "document": bank.policy.document},
                             "history": bank.policy.history()})

    @r.post("/ops/payments/reconcile")
    def reconcile_payments():
        """Ask the bank's payment system about payments it has not confirmed or declined. A bank runs this on a
        schedule; the hold on the customer's limit stays until the bank answers."""
        return JSONResponse({"reconciled": bank.payments.reconcile()})

    @r.get("/receipts/verify")
    def verify_receipts():
        return JSONResponse(bank.receipts.verify_chain())

    return r
