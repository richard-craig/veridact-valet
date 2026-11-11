"""
Consent Service: a standard consent ("mandate") model any application can use (docs/consent-service-openapi.yaml).

The UK Open Banking intent-based pattern, generalised with RFC 9396 authorization_details:

  1 app   POST /consent/v1/consents              (client-credentials token from the bank's IdP)  -> AwaitingAuthorisation
  2 app   sends the customer to the bank's IdP with consent_id (PAR)
  3 IdP   signs the customer in, hands them to the bank's consent screen (handoff.py); the customer approves and picks
          accounts                                                                               -> Authorised
  4 IdP   issues the app's DPoP-bound token carrying only a reference: valet_grant = consent_id
  5 bank  every API call asks POST /consent/v1/consent-decisions: permit, deny or step_up_required, with a receipt
  6 any   revoke (customer in the bank app, or the app)  -> Revoked; signed Security Event Token to the app's webhook

The consent is a first-class resource with its own id, status and lifecycle; access tokens only point at it, so a
revoke takes effect on the next call however long the token has left. Valet's AI-agent grants (grants.py) are the
same idea specialised for agents; in a bank deployment the two converge on this store.
"""
from __future__ import annotations

import asyncio
import calendar
import hashlib
import json
import os
import secrets
import string
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from ..common.crypto import Key, random_id
from ..common.dpop import DPoPError, check_proof
from ..common.money import rand, to_cents, to_str
from .config import SAST
from .context import Bank
from .tokens import TokenRejected

SCHEMA = """
CREATE TABLE IF NOT EXISTS consents (id TEXT PRIMARY KEY, client_id TEXT, status TEXT, status_reason TEXT,
    details TEXT, purpose TEXT, actor TEXT, resources TEXT, customer TEXT, metadata TEXT, created REAL,
    status_updated REAL, authorisation_expires REAL, authorised_at REAL, expires REAL, revoked_at REAL,
    last_used REAL, supersedes TEXT, superseded_by TEXT, version INTEGER, idem_key TEXT, idem_hash TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS consents_idem ON consents (client_id, idem_key);
CREATE TABLE IF NOT EXISTS consent_usage (consent_id TEXT, detail_index INTEGER, limit_index INTEGER, period TEXT,
    used INTEGER, reserved INTEGER, count INTEGER, PRIMARY KEY (consent_id, detail_index, limit_index, period));
CREATE TABLE IF NOT EXISTS consent_decisions (id TEXT PRIMARY KEY, consent_id TEXT, detail_index INTEGER,
    periods TEXT, amount INTEGER, status TEXT, created REAL);
CREATE TABLE IF NOT EXISTS consent_events (id TEXT PRIMARY KEY, client_id TEXT, consent_id TEXT, token TEXT,
    created REAL, delivered INTEGER DEFAULT 0, attempts INTEGER DEFAULT 0, last_error TEXT);
"""

ALNUM = string.ascii_letters + string.digits
STATUSES = ["AwaitingAuthorisation", "Authorised", "Rejected", "Revoked", "Expired", "Suspended"]
TERMINAL = {"Rejected", "Revoked", "Expired"}
AUTHORISATION_WINDOW = 15 * 60
EVENT_TYPE = "https://schemas.bank.example/events/consent/status_changed"

# ------------------------------------------------------------------ catalogue (the bank's policy, published)
TYPES: dict[str, dict[str, Any]] = {
    "account_information": {
        "description": "Read account data the customer selects.",
        "actions": ["read_accounts_basic", "read_accounts_detail", "read_balances", "read_transactions_basic",
                    "read_transactions_detail", "read_beneficiaries", "read_standing_orders", "read_statements"],
        "max_days": 365, "requires_actor": False, "amount": False},
    "payment_initiation": {
        "description": "One payment of a fixed amount to a fixed payee.",
        "actions": ["initiate_payment"], "max_days": 30, "requires_actor": False, "amount": True},
    "recurring_payment": {
        "description": "Repeated payments within per-payment and periodic limits (subscriptions, sweeping).",
        "actions": ["initiate_payment"], "max_days": 365, "requires_actor": False, "amount": True},
    "customer_profile": {
        "description": "Read or update the customer's contact details.",
        "actions": ["read_profile", "update_contact_details"], "max_days": 365, "requires_actor": False,
        "amount": False},
    "delegated_action": {
        "description": "Actions by a delegate (AI agent, adviser) on the customer's behalf, within limits.",
        "actions": ["transfer_between_own_accounts", "pay_existing_beneficiary"], "max_days": 365,
        "requires_actor": True, "amount": True},
}
PURPOSES: dict[str, dict[str, Any]] = {
    "affordability_assessment": {"display_text": "to check whether you can afford a loan or credit",
                                 "allowed_types": ["account_information", "customer_profile"]},
    "budgeting_insights": {"display_text": "to show you insights about your spending",
                           "allowed_types": ["account_information"]},
    "subscription_payment": {"display_text": "to collect a regular subscription you signed up for",
                             "allowed_types": ["recurring_payment"]},
    "single_payment": {"display_text": "to make one payment you asked for", "allowed_types": ["payment_initiation"]},
    "automated_savings": {"display_text": "to move money to your savings automatically",
                          "allowed_types": ["account_information", "delegated_action"]},
    "bill_payment": {"display_text": "to pay your bills to payees you have already saved",
                     "allowed_types": ["account_information", "delegated_action"]},
}
ACTION_WORDS = {"read_accounts_basic": "account names", "read_accounts_detail": "account details",
                "read_balances": "balances", "read_transactions_basic": "transactions",
                "read_transactions_detail": "transaction details", "read_beneficiaries": "saved payees",
                "read_standing_orders": "debit orders", "read_statements": "statements",
                "read_profile": "your contact details", "update_contact_details": "change your contact details",
                "transfer_between_own_accounts": "move money between your own accounts",
                "pay_existing_beneficiary": "pay payees you have already saved", "initiate_payment": "make payments"}


@dataclass
class ConsentClient:
    client_id: str
    name: str
    legal_entity: str = ""
    webhook_url: str = ""
    types: list[str] = field(default_factory=lambda: list(TYPES))


def clients_from_env() -> dict[str, ConsentClient]:
    raw = os.environ.get("VALET_CONSENT_CLIENTS", "").strip()
    items = json.loads(raw) if raw else [
        {"client_id": "acme-budgeting", "name": "Acme Budgeting", "legal_entity": "Acme Budgeting (Pty) Ltd (fictional)",
         "webhook_url": os.environ.get("ACME_WEBHOOK_URL", "")}]
    return {i["client_id"]: ConsentClient(**i) for i in items}


class Problem(Exception):
    """RFC 9457 problem details."""

    def __init__(self, status: int, error_code: str, title: str, detail: str = "", pointer: str | None = None):
        self.status, self.error_code, self.title, self.detail, self.pointer = status, error_code, title, detail, pointer

    def response(self, request: Request | None = None) -> JSONResponse:
        body: dict[str, Any] = {"type": f"https://errors.bank.example/consent/{self.error_code.replace('_', '-')}",
                                "title": self.title, "status": self.status, "error_code": self.error_code}
        if self.detail:
            body["detail"] = self.detail
        if self.pointer:
            body["errors"] = [{"pointer": self.pointer, "message": self.detail or self.title}]
        if request is not None and request.headers.get("x-fapi-interaction-id"):
            body["interaction_id"] = request.headers["x-fapi-interaction-id"]
        return JSONResponse(body, status_code=self.status, media_type="application/problem+json")


# ------------------------------------------------------------------ time and periods
def parse_time(value: Any, pointer: str) -> float:
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as e:
        raise Problem(400, "invalid_request", "Not an RFC 3339 timestamp", str(value), pointer) from e
    if dt.tzinfo is None:
        raise Problem(400, "invalid_request", "Timestamps need a UTC offset", str(value), pointer)
    return dt.timestamp()


def iso(ts: float | None) -> str | None:
    return None if ts is None else datetime.fromtimestamp(ts, SAST).isoformat(timespec="seconds")


def _add_months(dt: datetime, n: int) -> datetime:
    m = dt.month - 1 + n
    y, m = dt.year + m // 12, m % 12 + 1
    return dt.replace(year=y, month=m, day=min(dt.day, calendar.monthrange(y, m)[1]))


def period_bounds(period_type: str, alignment: str, anchor: float, now: float) -> tuple[float, float]:
    """The [start, end) of the period containing `now`. Calendar periods are in South African time."""
    t = datetime.fromtimestamp(now, SAST)
    months = {"Month": 1, "Half-year": 6, "Year": 12}.get(period_type)
    days = {"Day": 1, "Week": 7, "Fortnight": 14}.get(period_type)
    if alignment == "Calendar":
        day0 = t.replace(hour=0, minute=0, second=0, microsecond=0)
        if period_type == "Day":
            start = day0
        elif period_type == "Week":
            start = day0 - timedelta(days=day0.weekday())
        elif period_type == "Fortnight":
            monday = day0 - timedelta(days=day0.weekday())
            start = monday - timedelta(days=7 * ((monday.toordinal() // 7) % 2))
        elif period_type == "Month":
            start = day0.replace(day=1)
        elif period_type == "Half-year":
            start = day0.replace(month=1 if t.month <= 6 else 7, day=1)
        else:
            start = day0.replace(month=1, day=1)
        end = start + timedelta(days=days) if days else _add_months(start, months or 12)
        return start.timestamp(), end.timestamp()
    a = datetime.fromtimestamp(anchor, SAST)          # Consent alignment: periods start at authorised_at
    if days:
        k = int((now - anchor) // (days * 86400))
        start = a + timedelta(days=days * k)
        return start.timestamp(), (start + timedelta(days=days)).timestamp()
    start = a
    while _add_months(start, months or 12).timestamp() <= now:
        start = _add_months(start, months or 12)
    return start.timestamp(), _add_months(start, months or 12).timestamp()


def money(m: Any, pointer: str) -> int:
    if not isinstance(m, dict) or m.get("currency") != "ZAR":
        raise Problem(400, "invalid_authorization_details", "Amounts must be {amount, currency: ZAR}", "", pointer)
    try:
        return to_cents(m.get("amount", ""))
    except ValueError as e:
        raise Problem(400, "invalid_authorization_details", "Invalid amount", str(e), pointer) from e


def zar(cents: int) -> dict[str, str]:
    return {"amount": to_str(cents), "currency": "ZAR"}


# ------------------------------------------------------------------ the service
class ConsentService:
    def __init__(self, bank: Bank, clients: dict[str, ConsentClient] | None = None,
                 http: httpx.AsyncClient | None = None):
        self.bank, self.store = bank, bank.store
        self.store.db.executescript(SCHEMA)
        self.clients = clients if clients is not None else clients_from_env()
        in_memory = str(bank.cfg.database) == ":memory:"
        self.event_key = Key.generate() if in_memory else Key.load_or_create(bank.cfg.data_dir / "keys" / "consent-events.pem")
        self.http = http
        self.deliver_inline = False          # tests: deliver webhooks before returning

    # ---------------------------------------------------------- reading
    def row(self, consent_id: str) -> dict[str, Any] | None:
        r = self.store.one("SELECT * FROM consents WHERE id=?", consent_id)
        if not r:
            return None
        c = dict(r)
        for k in ("details", "purpose", "actor", "resources", "metadata"):
            c[k] = json.loads(c[k]) if c[k] else None
        return self._lazy_expiry(c)

    def _lazy_expiry(self, c: dict[str, Any]) -> dict[str, Any]:
        now = time.time()
        if c["status"] == "AwaitingAuthorisation" and now > c["authorisation_expires"]:
            return self.transition(c, "Expired", "authorisation_window_elapsed")
        if c["status"] in ("Authorised", "Suspended") and now > c["expires"]:
            return self.transition(c, "Expired", "expired")
        return c

    def view(self, c: dict[str, Any]) -> dict[str, Any]:
        base = self.bank.cfg.issuer + "/consent/v1/consents/" + c["id"]
        out = {"consent_id": c["id"], "status": c["status"], "status_reason": c["status_reason"],
               "client_id": c["client_id"], "authorization_details": c["details"], "purpose": c["purpose"],
               "resources": [{k: v for k, v in x.items() if not k.startswith("_")} for x in c["resources"] or []],
               "created_at": iso(c["created"]),
               "status_updated_at": iso(c["status_updated"]), "authorisation_expires_at": iso(c["authorisation_expires"]),
               "authorised_at": iso(c["authorised_at"]), "expires_at": iso(c["expires"]),
               "revoked_at": iso(c["revoked_at"]), "last_used_at": iso(c["last_used"]), "supersedes": c["supersedes"],
               "superseded_by": c["superseded_by"], "version": c["version"], "metadata": c["metadata"] or {},
               "links": {"self": base, "usage": base + "/usage"}}
        if c["actor"]:
            out["actor"] = c["actor"]
        if not out["status_reason"]:
            del out["status_reason"]
        return out

    def plain_summary(self, c: dict[str, Any]) -> str:
        cl = self.clients.get(c["client_id"])
        who = cl.name if cl else c["client_id"]
        if c["actor"]:
            who = f"{c['actor'].get('display_name') or c['actor']['id']} (an AI agent for {who})" \
                if c["actor"]["type"] == "ai_agent" else f"{c['actor'].get('display_name') or c['actor']['id']} for {who}"
        parts = []
        for d in c["details"]:
            words = [ACTION_WORDS.get(a, a) for a in d["actions"]]
            cp = d.get("control_parameters") or {}
            if d["type"] == "account_information":
                parts.append("see " + ", ".join(words))
            elif d["type"] == "payment_initiation":
                parts.append(f"make one payment of {rand(to_cents(d['instructed_amount']['amount']))} "
                             f"to {d['creditor']['name']}")
            elif d["type"] == "recurring_payment":
                lim = cp["periodic_limits"][0]
                cnt = f", at most {lim['max_count']} payment(s)" if lim.get("max_count") else ""
                payee = f" to {d['creditor']['name']}" if d.get("creditor") else ""
                parts.append(f"collect up to {rand(to_cents(lim['max_amount']['amount']))} a "
                             f"{lim['period_type'].lower()}{payee}{cnt}")
            elif d["type"] == "delegated_action":
                s = ", ".join(words)
                if cp.get("max_individual_amount"):
                    s += f", up to {rand(to_cents(cp['max_individual_amount']['amount']))} each"
                for lim in cp.get("periodic_limits", []):
                    s += f" and {rand(to_cents(lim['max_amount']['amount']))} a {lim['period_type'].lower()}"
                if cp.get("step_up_above"):
                    s += f"; anything over {rand(to_cents(cp['step_up_above']['amount']))} needs your approval"
                parts.append(s)
            else:
                parts.append(", ".join(words))
        on = ""
        if c["resources"]:
            on = " on " + " and ".join(r_["display"] for r_ in c["resources"])
        purpose = PURPOSES.get(c["purpose"]["code"], {}).get("display_text", c["purpose"]["code"])
        until = datetime.fromtimestamp(c["expires"], SAST).strftime("%-d %B %Y")
        return f"{who} can {'; '.join(parts)}{on} until {until}, {purpose}."

    # ---------------------------------------------------------- creating
    def validate(self, client: ConsentClient, body: dict[str, Any]) -> None:
        allowed_keys = {"authorization_details", "purpose", "expires_at", "actor", "supersedes", "customer_hint", "metadata"}
        extra = set(body) - allowed_keys
        if extra:
            raise Problem(400, "invalid_request", "Unknown fields", ", ".join(sorted(extra)), "/" + sorted(extra)[0])
        details = body.get("authorization_details")
        if not isinstance(details, list) or not 1 <= len(details) <= 10:
            raise Problem(400, "invalid_authorization_details", "authorization_details must list 1 to 10 items", "",
                          "/authorization_details")
        purpose = (body.get("purpose") or {}).get("code")
        if purpose not in PURPOSES:
            raise Problem(422, "unknown_purpose", "Unknown purpose code", str(purpose), "/purpose/code")
        expires = parse_time(body.get("expires_at"), "/expires_at")
        if expires <= time.time():
            raise Problem(422, "expiry_in_past", "expires_at is in the past", "", "/expires_at")
        needs_actor = False
        for i, d in enumerate(details):
            p = f"/authorization_details/{i}"
            t = TYPES.get(d.get("type")) if isinstance(d, dict) else None
            if not t:
                raise Problem(422, "unsupported_type", "Unsupported authorization_details type", str(d), p + "/type")
            if d["type"] not in client.types:
                raise Problem(422, "client_not_entitled", f"This client is not onboarded for {d['type']}", "", p + "/type")
            if d["type"] not in PURPOSES[purpose]["allowed_types"]:
                raise Problem(422, "purpose_not_allowed_for_type", f"Purpose {purpose} does not allow {d['type']}", "",
                              p + "/type")
            acts = d.get("actions")
            if not isinstance(acts, list) or not acts or any(a not in t["actions"] for a in acts):
                raise Problem(400, "invalid_authorization_details", f"actions must be from {t['actions']}", "",
                              p + "/actions")
            max_exp = time.time() + t["max_days"] * 86400 + 86400
            if expires > max_exp:
                raise Problem(422, "expiry_exceeds_max",
                              f"{d['type']} consents may last at most {t['max_days']} days",
                              f"Must be on or before {iso(max_exp)}", "/expires_at")
            needs_actor |= t["requires_actor"]
            cp = d.get("control_parameters") or {}
            if d["type"] == "payment_initiation":
                money(d.get("instructed_amount"), p + "/instructed_amount")
                if not (d.get("creditor") or {}).get("account", {}).get("identification"):
                    raise Problem(400, "invalid_authorization_details", "creditor.account is required", "", p + "/creditor")
            if d["type"] == "recurring_payment":
                money(cp.get("max_individual_amount"), p + "/control_parameters/max_individual_amount")
                if not cp.get("periodic_limits"):
                    raise Problem(400, "invalid_authorization_details", "periodic_limits are required", "",
                                  p + "/control_parameters/periodic_limits")
            for j, lim in enumerate(cp.get("periodic_limits", [])):
                lp = f"{p}/control_parameters/periodic_limits/{j}"
                if lim.get("period_type") not in ("Day", "Week", "Fortnight", "Month", "Half-year", "Year") or \
                        lim.get("period_alignment") not in ("Consent", "Calendar"):
                    raise Problem(400, "invalid_authorization_details", "Invalid period", "", lp)
                money(lim.get("max_amount"), lp + "/max_amount")
            for k in ("max_individual_amount", "step_up_above"):
                if k in cp:
                    money(cp[k], f"{p}/control_parameters/{k}")
        actor = body.get("actor")
        if needs_actor and not actor:
            raise Problem(422, "actor_required", "delegated_action needs an actor (who acts for the customer)", "", "/actor")
        if actor and (actor.get("type") not in ("ai_agent", "adviser", "sub_processor") or not actor.get("id")):
            raise Problem(400, "invalid_request", "actor needs type and id", "", "/actor")
        if body.get("supersedes"):
            old = self.row(body["supersedes"])
            if not old or old["client_id"] != client.client_id:
                raise Problem(422, "supersedes_invalid", "supersedes must name one of this client's consents", "",
                              "/supersedes")

    def create(self, client: ConsentClient, body: dict[str, Any], idem_key: str) -> tuple[dict[str, Any], bool]:
        h = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        prev = self.store.one("SELECT id, idem_hash FROM consents WHERE client_id=? AND idem_key=?", client.client_id, idem_key)
        if prev:
            if prev["idem_hash"] != h:
                raise Problem(409, "idempotency_conflict", "x-idempotency-key reused with a different body")
            return self.row(prev["id"]), False
        self.validate(client, body)
        now = time.time()
        cid = "cns_" + "".join(secrets.choice(ALNUM) for _ in range(24))
        self.store.x("INSERT INTO consents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     cid, client.client_id, "AwaitingAuthorisation", None, json.dumps(body["authorization_details"]),
                     json.dumps(body["purpose"]), json.dumps(body.get("actor")) if body.get("actor") else None,
                     json.dumps([]), None, json.dumps(body.get("metadata") or {}), now, now, now + AUTHORISATION_WINDOW,
                     None, parse_time(body["expires_at"], "/expires_at"), None, None, body.get("supersedes"), None, 1,
                     idem_key, h)
        c = self.row(cid)
        self.bank.receipts.append(grant_id=cid, agent=client.client_id, customer=None, action="consent_created",
                                  outcome="done", basis="client", detail={"types": [d["type"] for d in c["details"]],
                                                                          "purpose": c["purpose"]["code"]})
        return c, True

    # ---------------------------------------------------------- lifecycle
    def transition(self, c: dict[str, Any], status: str, reason: str, by: str = "bank") -> dict[str, Any]:
        if c["status"] == status:
            return c
        now = time.time()
        prev = c["status"]
        self.store.x("UPDATE consents SET status=?, status_reason=?, status_updated=?, revoked_at=? WHERE id=?",
                     status, reason, now, now if status == "Revoked" else c["revoked_at"], c["id"])
        c = {**c, "status": status, "status_reason": reason, "status_updated": now,
             "revoked_at": now if status == "Revoked" else c["revoked_at"]}
        self.bank.receipts.append(grant_id=c["id"], agent=c["client_id"], customer=c["customer"],
                                  action="consent_status", outcome=status, basis=by,
                                  detail={"previous": prev, "reason": reason})
        self.emit(c, prev)
        return c

    def authorise(self, c: dict[str, Any], customer: str, resources: list[dict[str, Any]]) -> dict[str, Any]:
        now = time.time()
        self.store.x("UPDATE consents SET customer=?, resources=?, authorised_at=? WHERE id=?", customer,
                     json.dumps(resources), now, c["id"])
        c = self.transition({**c, "customer": customer, "resources": resources, "authorised_at": now},
                            "Authorised", "customer_approved", by="customer")
        if c["supersedes"]:
            old = self.row(c["supersedes"])
            if old and old["status"] not in TERMINAL:
                self.store.x("UPDATE consents SET superseded_by=? WHERE id=?", c["id"], old["id"])
                self.transition(old, "Revoked", "superseded", by="customer")
        return c

    def revoke(self, c: dict[str, Any], reason: str, by: str) -> dict[str, Any]:
        if c["status"] in TERMINAL:
            return c
        if c["status"] == "AwaitingAuthorisation":
            return self.transition(c, "Rejected", "cancelled_by_client" if by == "client" else reason, by=by)
        return self.transition(c, "Revoked", reason, by=by)

    # ---------------------------------------------------------- webhooks (RFC 8417 Security Event Tokens)
    def emit(self, c: dict[str, Any], previous: str) -> None:
        now = int(time.time())
        jti = random_id("evt_")
        claims = {"iss": self.bank.cfg.issuer, "iat": now, "jti": jti, "aud": c["client_id"],
                  "events": {EVENT_TYPE: {"consent_id": c["id"], "status": c["status"], "previous_status": previous,
                                          "status_reason": c["status_reason"], "changed_at": iso(c["status_updated"])}}}
        token = self.event_key.sign(claims, headers={"typ": "secevent+jwt", "kid": "consent-events-1"})
        self.store.x("INSERT INTO consent_events (id, client_id, consent_id, token, created) VALUES (?,?,?,?,?)",
                     jti, c["client_id"], c["id"], token, time.time())
        cl = self.clients.get(c["client_id"])
        if cl and cl.webhook_url:
            if self.deliver_inline:
                return
            try:
                asyncio.get_running_loop().create_task(self.deliver(jti))
            except RuntimeError:
                pass                                 # no loop (sync caller): the outbox keeps it for retry

    async def deliver(self, jti: str) -> bool:
        ev = self.store.one("SELECT * FROM consent_events WHERE id=?", jti)
        cl = self.clients.get(ev["client_id"]) if ev else None
        if not ev or not cl or not cl.webhook_url or ev["delivered"]:
            return False
        http = self.http or httpx.AsyncClient(timeout=5)
        try:
            r = await http.post(cl.webhook_url, content=ev["token"], headers={"Content-Type": "application/secevent+jwt"})
            ok = 200 <= r.status_code < 300
            err = None if ok else f"HTTP {r.status_code}"
        except httpx.HTTPError as e:
            ok, err = False, str(e)[:200]
        self.store.x("UPDATE consent_events SET delivered=?, attempts=attempts+1, last_error=? WHERE id=?",
                     int(ok), err, jti)
        return ok

    async def flush(self) -> int:
        n = 0
        for ev in self.store.q("SELECT id FROM consent_events WHERE delivered=0 AND attempts<20 ORDER BY created"):
            n += await self.deliver(ev["id"])
        return n

    # ---------------------------------------------------------- usage and decisions
    def _limits(self, d: dict[str, Any]) -> list[dict[str, Any]]:
        cp = d.get("control_parameters") or {}
        lims = list(cp.get("periodic_limits") or [])
        if d["type"] == "payment_initiation":         # one payment, ever
            lims = [{"period_type": "Year", "period_alignment": "Consent",
                     "max_amount": d["instructed_amount"], "max_count": 1, "_lifetime": True}]
        return lims

    def _period(self, c: dict[str, Any], lim: dict[str, Any], now: float) -> tuple[str, float, float]:
        if lim.get("_lifetime"):
            return "lifetime", c["authorised_at"] or c["created"], c["expires"]
        s, e = period_bounds(lim["period_type"], lim["period_alignment"], c["authorised_at"] or c["created"], now)
        return f"{lim['period_type']}:{int(s)}", s, e

    def _usage(self, cid: str, di: int, li: int, period: str) -> dict[str, int]:
        r = self.store.one("SELECT used, reserved, count FROM consent_usage WHERE consent_id=? AND detail_index=? "
                           "AND limit_index=? AND period=?", cid, di, li, period)
        return dict(r) if r else {"used": 0, "reserved": 0, "count": 0}

    def _bump(self, cid: str, di: int, li: int, period: str, used: int = 0, reserved: int = 0, count: int = 0) -> None:
        self.store.x("""INSERT INTO consent_usage VALUES (?,?,?,?,?,?,?)
                        ON CONFLICT(consent_id, detail_index, limit_index, period) DO UPDATE SET
                        used=used+excluded.used, reserved=reserved+excluded.reserved, count=count+excluded.count""",
                     cid, di, li, period, used, reserved, count)

    def usage(self, c: dict[str, Any]) -> dict[str, Any]:
        now, out = time.time(), []
        for di, d in enumerate(c["details"]):
            for li, lim in enumerate(self._limits(d)):
                period, s, e = self._period(c, lim, now)
                u = self._usage(c["id"], di, li, period)
                out.append({"detail_index": di, "period_type": "Lifetime" if lim.get("_lifetime") else lim["period_type"],
                            "period_start": iso(s), "period_end": iso(e), "max_amount": lim["max_amount"],
                            "used_amount": zar(u["used"]), "reserved_amount": zar(u["reserved"]),
                            "used_count": u["count"], "max_count": lim.get("max_count")})
        return {"consent_id": c["id"], "as_of": iso(now), "limits": out}

    def decide(self, req: dict[str, Any], decider: str) -> dict[str, Any]:
        """The enforcement point: called by the bank's APIs on every protected call."""
        c = self.row(str(req.get("consent_id", "")))

        def answer(decision: str, reason: str, **extra: Any) -> dict[str, Any]:
            if c:
                self.bank.receipts.append(
                    grant_id=c["id"], agent=req.get("actor_id") or c["client_id"], customer=c["customer"],
                    action=f"{req.get('type')}:{req.get('action')}", outcome=decision, basis="consent", reason=reason,
                    decided_by=decider, detail={k: v for k, v in {"amount": req.get("amount"),
                                                                  "resource": (req.get("resource") or {}).get("resource_id"),
                                                                  **(req.get("context") or {})}.items() if v})
            return {"decision": decision, "reason": reason, "cache_ttl_seconds": extra.pop("cache_ttl_seconds", 0), **extra}

        if not c:
            return answer("deny", "consent_not_found")
        if c["client_id"] != req.get("client_id"):
            return answer("deny", "client_mismatch")
        st = c["status"]
        if st != "Authorised":
            return answer("deny", {"Revoked": "consent_revoked", "Expired": "consent_expired",
                                   "Suspended": "consent_suspended"}.get(st, "consent_not_authorised"))
        actor = c["actor"] or {}
        if (actor.get("id") or None) != (req.get("actor_id") or None):
            return answer("deny", "actor_mismatch")
        di, d = next(((i, x) for i, x in enumerate(c["details"])
                      if x["type"] == req.get("type") and req.get("action") in x["actions"]), (None, None))
        if d is None:
            return answer("deny", "action_not_granted")
        res = req.get("resource") or {}
        if res and res.get("resource_id") not in {r_["resource_id"] for r_ in c["resources"] or []}:
            return answer("deny", "resource_not_granted")
        now = time.time()
        self.store.x("UPDATE consents SET last_used=? WHERE id=?", now, c["id"])
        if not TYPES[d["type"]]["amount"]:
            cons = d.get("constraints") or {}
            keep = {k: cons[k] for k in ("transactions_from", "transactions_to") if k in cons}
            return answer("permit", "ok", cache_ttl_seconds=30, **({"constraints": keep} if keep else {}))
        # ---- amount-bearing actions
        if not req.get("amount"):
            return answer("deny", "action_not_granted")
        try:
            cents = money(req["amount"], "/amount")
        except Problem:
            return answer("deny", "action_not_granted")
        cp = d.get("control_parameters") or {}
        ctx = req.get("context") or {}
        if d["type"] == "payment_initiation":
            if cents != to_cents(d["instructed_amount"]["amount"]) or \
                    ctx.get("creditor_account", d["creditor"]["account"]["identification"]) != d["creditor"]["account"]["identification"]:
                return answer("deny", "action_not_granted")
        if d["type"] == "recurring_payment":
            if cp.get("valid_from") and now < parse_time(cp["valid_from"], ""):
                return answer("deny", "consent_not_authorised")
            if cp.get("valid_to") and now > parse_time(cp["valid_to"], ""):
                return answer("deny", "consent_expired")
            payee = ((d.get("creditor") or {}).get("account") or {}).get("identification")
            if payee and ctx.get("creditor_account") and ctx["creditor_account"] != payee:
                return answer("deny", "action_not_granted")
        if cp.get("max_individual_amount") and cents > to_cents(cp["max_individual_amount"]["amount"]):
            return answer("deny", "limit_exceeded")
        hours = cp.get("allowed_hours")
        if hours:
            local = datetime.now(SAST).strftime("%H:%M")
            if not hours["from"] <= local < hours["to"]:
                return answer("deny", "outside_allowed_hours")
        periods = []
        for li, lim in enumerate(self._limits(d)):
            period, _, _ = self._period(c, lim, now)
            u = self._usage(c["id"], di, li, period)
            if u["used"] + u["reserved"] + cents > to_cents(lim["max_amount"]["amount"]):
                return answer("deny", "limit_exceeded")
            if lim.get("max_count") and u["count"] + 1 > lim["max_count"]:
                return answer("deny", "limit_exceeded")
            periods.append([li, period])
        if cp.get("step_up_above") and cents > to_cents(cp["step_up_above"]["amount"]) and ctx.get("step_up") != "approved":
            return answer("step_up_required", "ok")
        if not req.get("reserve"):
            return answer("permit", "ok")
        did = random_id("dec_")
        with self.store.tx():
            self.store.db.execute("INSERT INTO consent_decisions VALUES (?,?,?,?,?,?,?)",
                                  (did, c["id"], di, json.dumps(periods), cents, "reserved", now))
        for li, period in periods:
            self._bump(c["id"], di, li, period, reserved=cents)
        return answer("permit", "ok", decision_id=did)

    def settle(self, did: str, outcome: str) -> None:
        r = self.store.one("SELECT * FROM consent_decisions WHERE id=?", did)
        if not r:
            raise Problem(404, "consent_not_found", "No such decision")
        if r["status"] != "reserved":
            raise Problem(409, "invalid_state_transition", f"Decision already {r['status']}")
        self.store.x("UPDATE consent_decisions SET status=? WHERE id=?", outcome, did)
        for li, period in json.loads(r["periods"]):
            if outcome == "confirmed":
                self._bump(r["consent_id"], r["detail_index"], li, period, used=r["amount"], reserved=-r["amount"], count=1)
            else:
                self._bump(r["consent_id"], r["detail_index"], li, period, reserved=-r["amount"])


# ------------------------------------------------------------------ HTTP
def routers(bank: Bank, svc: ConsentService) -> tuple[APIRouter, APIRouter]:
    r = APIRouter(prefix="/consent/v1")
    audience = os.environ.get("VALET_CONSENT_AUDIENCE", "valet-consent")

    def client_token(request: Request, scope: str) -> str:
        """A client-credentials token from the bank's IdP, sender-constrained with DPoP when the token says so."""
        auth = request.headers.get("Authorization", "")
        scheme, _, token = auth.partition(" ")
        if scheme not in ("Bearer", "DPoP") or not token:
            raise Problem(401, "invalid_token", "A client-credentials access token is required")
        try:
            claims = bank_verify_client_token(bank, token, audience)
        except TokenRejected as e:
            raise Problem(401, "invalid_token", "Access token rejected", str(e)) from e
        if (claims.get("cnf") or {}).get("jkt") or scheme == "DPoP":
            try:
                jkt = check_proof(request.headers.get("DPoP"), request.method, str(request.url), bank.store.seen_jti,
                                  access_token=token)
            except DPoPError as e:
                raise Problem(401, "invalid_token", "DPoP proof rejected", str(e)) from e
            if (claims.get("cnf") or {}).get("jkt") != jkt:
                raise Problem(401, "invalid_token", "Token is bound to a different key")
        if scope not in str(claims.get("scope", "")).split():
            raise Problem(403, "insufficient_scope", f"Token lacks scope {scope}")
        return claims["client_id"]

    def app_client(request: Request, scope: str) -> ConsentClient:
        cid = client_token(request, scope)
        cl = svc.clients.get(cid)
        if not cl:
            raise Problem(403, "client_not_entitled", "This client is not onboarded to the consent service")
        return cl

    def owned(cl: ConsentClient, consent_id: str) -> dict[str, Any]:
        c = svc.row(consent_id)
        if not c or c["client_id"] != cl.client_id:
            raise Problem(404, "consent_not_found", "No such consent for this caller")
        return c

    def interaction(request: Request) -> str:
        return request.headers.get("x-fapi-interaction-id") or random_id("")

    def reply(request: Request, body: Any, status: int = 200, headers: dict[str, str] | None = None) -> Response:
        h = {"x-fapi-interaction-id": interaction(request), **(headers or {})}
        if body is None:
            return Response(status_code=status, headers=h)
        return JSONResponse(body, status_code=status, headers=h)

    @r.post("/consents")
    async def create_consent(request: Request):
        cl = app_client(request, "consents:write")
        key = request.headers.get("x-idempotency-key", "")
        if not 8 <= len(key) <= 64:
            raise Problem(400, "invalid_request", "x-idempotency-key header (8-64 characters) is required")
        try:
            body = await request.json()
        except ValueError as e:
            raise Problem(400, "invalid_request", "Body must be JSON") from e
        if not isinstance(body, dict):
            raise Problem(400, "invalid_request", "Body must be a JSON object")
        c, created = svc.create(cl, body, key)
        v = svc.view(c)
        return reply(request, v, 201 if created else 200, {"Location": v["links"]["self"]})

    @r.get("/consents")
    async def list_consents(request: Request, status: str = "", type: str = "", page_size: int = 25):
        cl = app_client(request, "consents:read")
        rows = [svc.row(x["id"]) for x in bank.store.q("SELECT id FROM consents WHERE client_id=? ORDER BY created DESC",
                                                        cl.client_id)]
        want = set(filter(None, status.split(",")))
        rows = [c for c in rows if (not want or c["status"] in want) and (not type or any(d["type"] == type for d in c["details"]))]
        return reply(request, {"items": [svc.view(c) for c in rows[:max(1, min(page_size, 100))]], "next_cursor": None})

    @r.get("/consents/{consent_id}")
    async def get_consent(request: Request, consent_id: str):
        return reply(request, svc.view(owned(app_client(request, "consents:read"), consent_id)))

    @r.delete("/consents/{consent_id}")
    async def revoke_consent(request: Request, consent_id: str, reason: str = ""):
        cl = app_client(request, "consents:write")
        svc.revoke(owned(cl, consent_id), "revoked_by_client", by="client")
        return reply(request, None, 204)

    @r.get("/consents/{consent_id}/usage")
    async def get_usage(request: Request, consent_id: str):
        return reply(request, svc.usage(owned(app_client(request, "consents:read"), consent_id)))

    @r.post("/consent-decisions")
    async def decide(request: Request):
        rs = client_token(request, "consents:decide")
        return reply(request, svc.decide(await request.json(), decider=rs))

    @r.patch("/consent-decisions/{decision_id}")
    async def settle(request: Request, decision_id: str):
        client_token(request, "consents:decide")
        outcome = (await request.json()).get("outcome")
        if outcome not in ("confirmed", "released"):
            raise Problem(400, "invalid_request", "outcome must be confirmed or released")
        svc.settle(decision_id, outcome)
        return reply(request, None, 204)

    @r.get("/catalogue/types")
    async def types(request: Request):
        app_client(request, "consents:read")
        return reply(request, {"types": [{"type": k, "description": v["description"], "actions": v["actions"],
                                          "max_duration": f"P{v['max_days']}D", "requires_actor": v["requires_actor"],
                                          "requires_signed_request": v["amount"], "client_entitlement_required": True}
                                         for k, v in TYPES.items()]})

    @r.get("/catalogue/purposes")
    async def purposes(request: Request):
        app_client(request, "consents:read")
        return reply(request, {"purposes": [{"code": k, **v} for k, v in PURPOSES.items()]})

    @r.get("/jwks")
    async def jwks():
        """Keys that sign consent events (webhooks), so applications can verify them."""
        return {"keys": [{**svc.event_key.jwk, "kid": "consent-events-1", "use": "sig", "alg": "ES256"}]}

    # ---- the customer's own channel (first party: the bank app session)
    from .web import current_customer, csrf_ok, csrf_token, render  # noqa: E402  (avoid import cycle)

    def customer(request: Request) -> dict[str, Any]:
        cus = current_customer(bank, request)
        if not cus:
            raise Problem(401, "invalid_token", "Sign in to the bank app")
        return cus

    def mine(cus: dict[str, Any]) -> list[dict[str, Any]]:
        return [svc.row(x["id"]) for x in bank.store.q("SELECT id FROM consents WHERE customer=? ORDER BY authorised_at DESC",
                                                        cus["id"])]

    def customer_view(c: dict[str, Any]) -> dict[str, Any]:
        cl = svc.clients.get(c["client_id"])
        return {**svc.view(c), "client_display": {"name": cl.name if cl else c["client_id"],
                                                  "legal_entity": cl.legal_entity if cl else ""},
                "plain_language_summary": svc.plain_summary(c)}

    @r.get("/customers/me/consents")
    async def my_consents(request: Request, status: str = ""):
        want = set(filter(None, status.split(",")))
        return {"items": [customer_view(c) for c in mine(customer(request)) if not want or c["status"] in want],
                "next_cursor": None}

    @r.delete("/customers/me/consents/{consent_id}")
    async def revoke_mine(request: Request, consent_id: str):
        cus = customer(request)
        c = svc.row(consent_id)
        if not c or c["customer"] != cus["id"]:
            raise Problem(404, "consent_not_found", "No such consent")
        svc.revoke(c, "revoked_by_customer", by="customer")
        return Response(status_code=204)

    @r.get("/docs", response_class=HTMLResponse)
    async def docs():
        return HTMLResponse(SWAGGER)

    @r.get("/openapi.yaml")
    async def spec():
        from pathlib import Path
        p = Path(__file__).resolve().parents[2] / "docs" / "consent-service-openapi.yaml"
        text = p.read_text() if p.exists() else ""
        text = text.replace("https://api.sandbox.bank.example/consent/v1", bank.cfg.issuer + "/consent/v1", 1)
        return Response(text, media_type="application/yaml")

    # ---- bank app pages: connected apps
    web = APIRouter()

    @web.get("/app/connected-apps", response_class=HTMLResponse)
    def connected(request: Request):
        cus = current_customer(bank, request)
        if not cus:
            return RedirectResponse("/login?next=/app/connected-apps", 303)
        items = [customer_view(c) for c in mine(cus)]
        return render(request, "connected_apps.html", bank, customer=cus, items=items, csrf=csrf_token(bank, cus["id"]))

    @web.post("/app/connected-apps/{consent_id}/revoke")
    async def revoke_page(request: Request, consent_id: str):
        cus = current_customer(bank, request)
        form = await request.form()
        if not cus or not csrf_ok(bank, cus["id"], str(form.get("csrf", ""))):
            return HTMLResponse("Not allowed", status_code=403)
        c = svc.row(consent_id)
        if c and c["customer"] == cus["id"]:
            svc.revoke(c, "revoked_by_customer", by="customer")
        return RedirectResponse("/app/connected-apps", 303)

    return r, web


def bank_verify_client_token(bank: Bank, token: str, audience: str) -> dict[str, Any]:
    """Verify a client-credentials token from one of the bank's IdPs (no consent reference needed)."""
    import jwt as _jwt
    try:
        iss = _jwt.decode(token, options={"verify_signature": False}).get("iss", "")
    except _jwt.PyJWTError as e:
        raise TokenRejected(f"unreadable token: {e}") from e
    ext = bank.external_issuers.get(iss)
    if not ext:
        raise TokenRejected("token from an issuer this bank does not accept")
    return ext.verify_client(token, audience)


SWAGGER = """<!doctype html><html><head><title>Consent Service API</title><meta charset="utf-8">
<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"></head><body>
<div id="ui"></div><script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>SwaggerUIBundle({url: "openapi.yaml", dom_id: "#ui", deepLinking: true});</script></body></html>"""
