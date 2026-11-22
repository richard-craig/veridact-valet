"""
The Valet decision service (docs/decision-service.md): the decision point the bank's own MCP server and APIs ask.

The bank's servers enforce. Before every action they ask Valet, over the OpenID AuthZEN Authorization API 1.0,
"may this agent do this, for this customer, right now?". Requests follow the AuthZEN COAZ-MCP binding (the human is
the subject; the agent is in context). For money there is a small extension, reserve, commit and release:

    evaluation ─► reserved ─► sent ─► committed
        │            │          ├──► released (declined)
        │            │          └──► unknown ──► committed | released   (only on the bank's answer)
        │            └──► released (not sent, or expired)
        └─► approval_required ─(customer approves)─► reserved

A reservation is a payment intent (valet/bank/payments.py): its id is the idempotency key the bank's server gives its
own payment system. Valet never moves money. It decides, holds the amount against the mandate, and records what
happened in a signed receipt.

Payments that need the customer come back as a requestable denial, in the form of the AuthZEN Access Request and
Approval Profile (AARP): `decision: false` with `context.access_request`. The bank's server submits the access request,
Valet asks the customer in the bank's own app, and the bank's server re-evaluates with `context.approval` once the
task is approved. A payment approval is single use.

This module is the logic. api.py publishes it over HTTP; the bank's server reaches it through client.py, in-process
or over the network, and fails closed either way.
"""
from __future__ import annotations

import collections
import hashlib
import hmac
import json
import secrets
import threading
import time
from typing import Any

from ..bank import levels as L
from ..bank import mandate
from ..bank.authz import payment_detail
from ..bank.registry import RegistryUnavailable
from ..common.crypto import digest, random_id
from ..common.money import CURRENCY, to_cents, to_str

# What each action needs from the mandate, and what kind of action it is.
ACTIONS: dict[str, dict[str, str]] = {
    "list_accounts": {"needs": "valet_accounts", "kind": "read"},
    "get_balance": {"needs": "valet_accounts", "kind": "read", "account": "valet_accounts"},
    "list_transactions": {"needs": "valet_accounts", "kind": "read", "account": "valet_accounts"},
    "list_payees": {"needs": "valet_payments", "kind": "read"},
    "pay_existing_payee": {"needs": "valet_payments", "kind": "pay"},
    "get_payment_status": {"needs": "valet_payments", "kind": "status"},
}
PAYMENT_ACTIONS = ("pay_existing_payee", "get_payment_status")

# Valet's reasons (context.reason) and the MCP reference server's reason codes for them. The first seven are the Valet
# profile's (docs/valet-profile.md §3); the rest are about the mandate, the agent or the request.
MCP_CODES: dict[str, str] = {
    **mandate.MCP_CODES,
    "approved_payer": "CUSTOMER_APPROVAL_REQUIRED", "over_approval_threshold": "CUSTOMER_APPROVAL_REQUIRED",
    "bearer_tier": "CUSTOMER_APPROVAL_REQUIRED", "assistant_ceiling": "CUSTOMER_APPROVAL_REQUIRED",
    "not_permitted": "TOOL_NOT_IN_MANDATE", "account_not_on_mandate": "ACCOUNT_NOT_IN_MANDATE",
    "unknown_mandate": "UNKNOWN_MANDATE", "mandate_paused": "MANDATE_PAUSED", "mandate_revoked": "MANDATE_REVOKED",
    "mandate_expired": "MANDATE_EXPIRED", "agent_denied": "AGENT_DENIED", "agent_untrusted": "AGENT_UNTRUSTED",
    "registry_unavailable": "REGISTRY_UNAVAILABLE", "assistant_withdrawn": "ASSISTANT_WITHDRAWN",
    "assistant_suspended": "ASSISTANT_SUSPENDED", "assistant_not_verified": "ASSISTANT_NOT_VERIFIED",
    "too_many_pending": "TOO_MANY_PENDING", "idempotency_key_required": "IDEMPOTENCY_KEY_REQUIRED",
    "idempotency_key_reused": "IDEMPOTENCY_KEY_REUSED", "invalid_amount": "INVALID_AMOUNT",
    "unknown_payment": "UNKNOWN_PAYMENT", "approval_pending": "CUSTOMER_APPROVAL_REQUIRED",
    "customer_declined": "CUSTOMER_DECLINED", "approval_expired": "APPROVAL_EXPIRED", "cancelled": "CANCELLED",
}
# Reasons that end the request. Anything else (approval reasons) is a requestable denial.
APPROVABLE = ("approved_payer", "over_approval_threshold", "bearer_tier", "assistant_ceiling")

STATE = {"approval_required": "approval_required", "reserved": "reserved", "executing": "sent",
         "cancelling": "sent", "unknown_outcome": "unknown", "confirmed": "committed", "failed": "released",
         "cancelled": "released"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS decision_requests (intent_id TEXT PRIMARY KEY, evaluation_id TEXT, binding_hash TEXT,
    task_id TEXT, created REAL);
CREATE TABLE IF NOT EXISTS decision_keys (name TEXT PRIMARY KEY, value TEXT);
"""


class Denied(Exception):
    """A deny decision, raised inside evaluate() and turned into an AuthZEN `decision: false`."""

    def __init__(self, reason: str, message: str, **context: Any):
        self.reason, self.message, self.context = reason, message, context


class BadRequest(Exception):
    """The request cannot be evaluated (AuthZEN 400; MCP -32602)."""


class Conflict(Exception):
    """A reservation transition that is not allowed (HTTP 409)."""


def _h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class DecisionService:
    def __init__(self, bank: Any, base_url: str | None = None, log_size: int = 50):
        self.bank, self.store = bank, bank.store
        self.base = (base_url or bank.cfg.issuer).rstrip("/")
        self.store.db.executescript(SCHEMA)
        self.store.x("INSERT OR IGNORE INTO decision_keys VALUES ('binding', ?)", secrets.token_urlsafe(32))
        self._binding_key = self.store.one("SELECT value FROM decision_keys WHERE name='binding'")["value"].encode()
        # The last decisions, for the bank's operations page: what crossed the wire, request and response.
        self.log: collections.deque[dict[str, Any]] = collections.deque(maxlen=log_size)
        self._log_lock = threading.Lock()

    # ================================================================ metadata
    def metadata(self) -> dict[str, Any]:
        """/.well-known/authzen-configuration (AuthZEN §9), plus the AARP and Valet members. Receivers ignore members
        they do not know."""
        b = self.base
        return {"policy_decision_point": b,
                "access_evaluation_endpoint": b + "/access/v1/evaluation",
                "access_evaluations_endpoint": b + "/access/v1/evaluations",
                "access_request_endpoint": b + "/access/v1/access_requests",
                "valet_reservations_endpoint": b + "/valet/v1/reservations",
                "valet_profile": "https://github.com/veridactlabs/veridact-valet/blob/main/docs/valet-profile.md",
                "valet_reasons": sorted(MCP_CODES)}

    # ================================================================ evaluation
    def evaluate(self, req: dict[str, Any]) -> dict[str, Any]:
        """POST /access/v1/evaluation. A deny is a decision, never an HTTP error."""
        try:
            out = self._evaluate(req)
        except Denied as d:
            out = {"decision": False, "context": {"reason": d.reason, "reason_admin": {"en": d.message},
                                                  "evaluation_id": random_id("ev", 10), **d.context}}
        self._remember("evaluation", req, out)
        return out

    def evaluations(self, req: dict[str, Any]) -> dict[str, Any]:
        """POST /access/v1/evaluations: one call to filter tools/list. Nothing is reserved and no receipt is written."""
        defaults = {k: req.get(k) for k in ("subject", "resource", "context") if req.get(k) is not None}
        results = []
        for item in req.get("evaluations") or []:
            one = {**defaults, **item, "context": {**(defaults.get("context") or {}), **(item.get("context") or {})}}
            try:
                self._admit(one, writes=False)
                results.append({"decision": True})
            except Denied as d:
                results.append({"decision": False, "context": {"reason": d.reason}})
        out = {"evaluations": results}
        self._remember("evaluations", req, out)
        return out

    def _admit(self, req: dict[str, Any], writes: bool = True) -> tuple[dict[str, Any], str, dict[str, Any]]:
        """The checks every action passes before its own: the mandate is live, the agent is the mandate's agent and
        still trusted, and the action is in the mandate. Returns (grant, action, context)."""
        ctx = req.get("context") or {}
        action = str((req.get("action") or {}).get("name") or "")
        if action not in ACTIONS:
            raise BadRequest(f"unknown action {action!r}")
        grant = self.store.grant(str(ctx.get("valet_grant") or ""))
        if not grant or grant["client_id"] != str(ctx.get("agent") or ""):
            raise Denied("unknown_mandate", "no such mandate for this agent")
        rec = lambda reason, **kw: writes and self._receipt(grant, action, ctx, "refused", reason, **kw)
        if grant["status"] != "active":
            reason = {"paused": "mandate_paused", "revoked": "mandate_revoked"}.get(grant["status"], "mandate_expired")
            rec(reason)
            raise Denied(reason, f"the customer's mandate is {grant['status']}")
        why = self.bank.denied(grant["client_id"], grant.get("jkt"))
        if why:
            rec("agent_denied")
            raise Denied("agent_denied", "the bank has stopped this agent")
        self._check_assistant(grant, action, ctx, rec)
        try:
            trusted = self.bank.registry.is_trusted(grant["client_id"], for_payment=action in PAYMENT_ACTIONS)
        except RegistryUnavailable:
            rec("registry_unavailable")
            raise Denied("registry_unavailable", "the bank cannot check this agent right now")
        if not trusted:
            rec("agent_untrusted")
            raise Denied("agent_untrusted", "the bank no longer accepts this agent")
        if not L.find(grant["details"], ACTIONS[action]["needs"]):
            rec("not_permitted")
            raise Denied("not_permitted", f"{action} is not allowed by the customer's mandate")
        return grant, action, ctx

    def _check_assistant(self, grant: dict[str, Any], action: str, ctx: dict[str, Any], rec: Any) -> None:
        """Lane A: a mainstream assistant's known-assistant entry (context.veridact) must be valid. The bank's server
        checks the entry; Valet applies it. Unavailable: payments fail closed, reads may continue."""
        known = getattr(self.bank, "known_assistants", None)
        if not known or not known.covers(grant["client_id"]):
            return
        v = ctx.get("veridact") or {}
        status = v.get("status")
        if status == "valid":
            return
        if status in ("withdrawn", "suspended"):
            reason = f"assistant_{status}"
            rec(reason)
            raise Denied(reason, f"Veridact has {status} this assistant ({v.get('operator') or grant['client_id']})")
        if status == "unavailable" and action not in PAYMENT_ACTIONS:
            return
        rec("assistant_not_verified")
        raise Denied("assistant_not_verified", "this assistant has no valid Veridact known-assistant entry")

    def _evaluate(self, req: dict[str, Any]) -> dict[str, Any]:
        grant, action, ctx = self._admit(req)
        kind = ACTIONS[action]["kind"]
        resource = req.get("resource") or {}
        if kind == "pay":
            return self._pay(grant, req, ctx)
        constraints: dict[str, Any] = {}
        if ACTIONS[action].get("account"):
            acct = str(resource.get("id") or "")
            d = L.find(grant["details"], "valet_accounts")
            if acct not in (d.get("accounts") or []):
                self._receipt(grant, action, ctx, "refused", "account_not_on_mandate")
                raise Denied("account_not_on_mandate", "that account is not shared with this agent")
        if action == "list_accounts":
            constraints["accounts"] = list(L.find(grant["details"], "valet_accounts").get("accounts") or [])
        if action == "list_transactions":
            constraints["history_days"] = int(L.find(grant["details"], "valet_accounts").get("history_days", 90))
        if action == "list_payees":
            named = L.payees(grant["details"])
            constraints["payees"] = None if named is None else sorted(named)
        if kind == "status":
            return {"decision": True, "context": {"valet": {"outcome": "allowed", "constraints": constraints}}}
        detail = {k: str(v)[:40] for k, v in (("account_id", resource.get("id")), ("days", ctx.get("days"))) if v}
        receipt = self._receipt(grant, action, ctx, "allowed", None, detail=detail)
        return {"decision": True, "context": {"valet": {"outcome": "allowed", "constraints": constraints,
                                                        "receipt": receipt["hash"]}}}

    # ---------------------------------------------------------------- money
    def _pay(self, grant: dict[str, Any], req: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
        if ctx.get("approval"):
            return self._reevaluate(grant, ctx)
        store, cfg = self.store, self.bank.cfg
        key = str(ctx.get("idempotency_key") or "")
        pay = ctx.get("payment") or {}
        frm = str((req.get("resource") or {}).get("id") or "")
        reason = str(ctx.get("agent_reason") or "")[:200]
        tier = "dpop" if ctx.get("token_tier") == "dpop" else "bearer"
        channel = "mcp_gateway" if ctx.get("channel", "mcp") == "mcp" else "api"
        refuse = lambda code, msg: self._refuse_payment(grant, ctx, code, msg, pay, tier, reason)
        if not 8 <= len(key) <= 64:
            raise refuse("idempotency_key_required", "give an idempotency key of 8 to 64 characters")
        payee = store.one("SELECT * FROM beneficiaries WHERE id=? AND customer=?", str(pay.get("payee") or ""),
                          grant["customer"])
        if not payee:
            raise refuse("new_recipient", "only payees the customer has already saved can be paid; agents can never "
                                          "add new payees")
        p = L.find(grant["details"], "valet_payments")
        if frm not in (p.get("accounts") or []):
            raise refuse("account_not_on_mandate", "that account is not shared for payments")
        if str(pay.get("currency") or CURRENCY) != CURRENCY:
            raise refuse("invalid_amount", f"payments are in {CURRENCY}")
        try:
            cents = to_cents(pay.get("amount", ""))
        except ValueError:
            raise refuse("invalid_amount", "amount must be in rands, e.g. 640.00")
        if cents <= 0:
            raise refuse("invalid_amount", "amount must be more than zero")
        detail = payment_detail(frm, payee["name"], payee["account"], cents, str(pay.get("reference") or "")[:20])
        request_digest = digest(detail)
        now = time.time()
        with store.tx():
            existing = self.bank.payments.by_key(grant["id"], key)
            if existing:
                if existing["request_digest"] != request_digest:
                    refusal = ("idempotency_key_reused", "that idempotency key was used for another payment")
                else:
                    refusal = None
                result = None if refusal else self._replay(grant, existing)
            else:
                check = mandate.check_payment(store, grant, payee["account"], cents, *self._waiting(grant["id"]))
                pending = self._waiting(grant["id"])[1]
                ceiling = self._ceiling(grant, ctx)
                if check.reason in mandate.LIMIT_REASONS:
                    # The same rules, in the same order, as the direct API (mandate.py). Here they are refusals: an
                    # approval never widens the mandate.
                    waits = " (counting payments already waiting for approval)" \
                        if check.reason in ("over_monthly_count", "over_monthly_limit") else ""
                    refusal, result = (check.reason, check.text + waits), None
                elif not check.covered or tier == "bearer" or ceiling == "approved_payer":
                    if pending >= cfg.max_pending_approvals:
                        refusal, result = ("too_many_pending", "too many payments are already waiting for the "
                                                               "customer"), None
                    else:
                        refusal = None
                        why_code = check.reason or ("bearer_tier" if tier == "bearer" else "assistant_ceiling")
                        words = {"bearer_tier": "this assistant connects with a bearer token, so the customer "
                                                "approves every payment",
                                 "assistant_ceiling": "Veridact's ceiling for this assistant is Approved payer"}
                        intent = self.bank.payments.create(
                            grant, key, request_digest, detail, cents, "approval_required", "approval",
                            reason=words.get(why_code, check.text), expires=now + max(cfg.approval_ttl, 600),
                            channel=channel, reason_code=why_code, instruction=reason)
                        result = ("approval", intent)
                else:
                    refusal = None
                    intent = self.bank.payments.create(grant, key, request_digest, detail, cents, "reserved", "grant",
                                                       expires=now + 600, channel=channel, instruction=reason)
                    result = ("reserved", intent)
        if refusal:
            raise refuse(*refusal)
        if result[0] == "replay":
            return result[1]
        intent = result[1]
        if result[0] == "approval":
            binding = self._binding(intent["id"])
            evaluation_id = random_id("ev", 10)
            store.x("INSERT INTO decision_requests VALUES (?,?,?,?,?)", intent["id"], evaluation_id, _h(binding), None,
                    now)
            rec = self._receipt(grant, "pay_existing_payee", ctx, "held", intent["reason_code"],
                                codes=["CUSTOMER_APPROVAL_REQUIRED"], payment_intent=intent["id"],
                                detail=self._summary(detail), tier=tier, reason_code=intent["reason_code"])
            return self._requestable(intent, evaluation_id, binding, rec["hash"])
        rec = self._receipt(grant, "pay_existing_payee", ctx, "reserved", None, payment_intent=intent["id"],
                            detail=self._summary(detail), tier=tier)
        return {"decision": True, "context": {"valet": {"outcome": "reserved", **self._reservation_ref(intent),
                                                        "receipt": rec["hash"]}}}

    def _replay(self, grant: dict[str, Any], intent: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """The same payment asked for again (a retry): the same reservation and the same decision. Nothing new is held."""
        if intent["status"] == "approval_required":
            row = self.store.one("SELECT * FROM decision_requests WHERE intent_id=?", intent["id"])
            binding = self._binding(intent["id"])             # the same binding token for the same evaluation
            return "replay", self._requestable(intent, row["evaluation_id"] if row else random_id("ev", 10), binding,
                                               None)
        ok = intent["status"] not in ("failed", "cancelled")
        return "replay", {"decision": ok, "context": {
            **({} if ok else {"reason": "cancelled" if intent["status"] == "cancelled" else "unknown_payment"}),
            "valet": {"outcome": "reserved" if ok else "released", **self._reservation_ref(intent), "replay": True}}}

    def _requestable(self, intent: dict[str, Any], evaluation_id: str, binding: str, receipt: str | None) -> dict[str, Any]:
        """A requestable denial (AARP): the amount stays held while the customer decides."""
        row = self.store.one("SELECT task_id FROM decision_requests WHERE intent_id=?", intent["id"])
        return {"decision": False, "context": {
            "reason": intent["reason_code"], "evaluation_id": evaluation_id,
            "reason_user": {"en": intent["reason"] or "the customer must approve this payment"},
            "access_request": {"endpoint": self.base + "/access/v1/access_requests", "binding_token": binding,
                               "expires_at": int(intent["expires"])},
            "valet": {"outcome": "approval_required", **self._reservation_ref(intent),
                      **({"task": row["task_id"]} if row and row["task_id"] else {}),
                      **({"receipt": receipt} if receipt else {})}}}

    def _refuse_payment(self, grant, ctx, code, msg, pay, tier, reason) -> Denied:
        self._receipt(grant, "pay_existing_payee", ctx, "refused", code, tier=tier, agent_supplied_instruction=reason,
                      detail={"payee_id": pay.get("payee"), "amount": pay.get("amount"),
                              "reference": pay.get("reference")})
        return Denied(code, msg[0].upper() + msg[1:] + ".")

    def _ceiling(self, grant: dict[str, Any], ctx: dict[str, Any]) -> str | None:
        """Veridact's recommended ceiling for a known assistant: the bank may lower it, never raise it."""
        level = (ctx.get("veridact") or {}).get("max_level")
        return level if level in L.LEVELS else None

    def _waiting(self, grant_id: str) -> tuple[int, int]:
        """Payments asked for that wait for the customer: they count against the month's limit and count."""
        rows = self.store.q(
            "SELECT pi.amount FROM payment_intents pi LEFT JOIN approvals a ON a.id = pi.approval "
            "WHERE pi.grant_id=? AND pi.status='approval_required' AND pi.expires>? AND pi.channel='mcp_gateway' "
            "AND (pi.approval IS NULL OR (a.status IN ('pending','approved') AND a.consumed=0 AND a.expires>?))",
            grant_id, time.time(), time.time())
        return sum(r["amount"] for r in rows), len(rows)

    def _reevaluate(self, grant: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
        """After the customer approved: the same reservation becomes `reserved`. The approval is single use."""
        task = str((ctx.get("approval") or {}).get("id") or "")
        ap = self.store.one("SELECT * FROM approvals WHERE id=? AND grant_id=?", task, grant["id"])
        intent = self.bank.payments.by_approval(grant["id"], task) if ap else None
        if not ap or not intent:
            raise Denied("unknown_payment", "no such payment request for this mandate")
        if ap["status"] == "denied":
            raise Denied("customer_declined", "the customer declined", next_action="none")
        if ap["status"] != "approved":
            if ap["status"] == "pending" and ap["expires"] > time.time():
                raise Denied("approval_pending", "still waiting for the customer")
            raise Denied("approval_expired", "the approval request expired", next_action="none")
        with self.store.tx():
            spent = (self.store.db.execute("UPDATE approvals SET consumed=1 WHERE id=? AND consumed=0", (task,)).rowcount
                     == 1 and self.bank.payments.reserve_approved(intent, task))
        if not spent:
            raise Denied("approval_expired", "this approval has already been used", next_action="none")
        intent = self.bank.payments.get(intent["id"])
        return {"decision": True, "context": {"valet": {"outcome": "reserved", **self._reservation_ref(intent),
                                                        "approval": task}}}

    # ================================================================ access requests (AARP)
    def access_request(self, body: dict[str, Any]) -> dict[str, Any]:
        """POST /access/v1/access_requests with the binding token from a requestable denial. Asks the customer in the
        bank's own app. Idempotent: the same evaluation gives the same task."""
        binding = str(body.get("binding_token") or "")
        row = self.store.one("SELECT * FROM decision_requests WHERE binding_hash=?", _h(binding)) if binding else None
        if not row:
            raise BadRequest("unknown or expired binding_token")
        intent = self.bank.payments.get(row["intent_id"])
        grant = self.store.grant(intent["grant_id"])
        if row["task_id"]:
            out = self.task(row["task_id"])
        elif intent["status"] != "approval_required" or intent["expires"] < time.time():
            raise BadRequest("this payment can no longer be approved")
        else:
            aid, now = random_id("ar", 12), time.time()
            who = self._agent_name(grant["client_id"])
            message = f"{who} says: {intent.get('instruction') or 'no reason given'}"[:120]
            with self.store.tx():
                self.store.db.execute("INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?,?,0,0)",
                                      (aid, grant["id"], grant["client_id"], json.dumps(intent["detail"]),
                                       intent["request_digest"], message, intent["reason"], "pending", now,
                                       intent["expires"]))
                self.store.db.execute("UPDATE payment_intents SET approval=?, updated=? WHERE id=?",
                                      (aid, now, intent["id"]))
                self.store.db.execute("UPDATE decision_requests SET task_id=? WHERE intent_id=?", (aid, intent["id"]))
            out = self.task(aid)
        self._remember("access_request", {"binding_token": "…"}, out)
        return out

    def task(self, task_id: str) -> dict[str, Any]:
        """GET /access/v1/access_requests/{id}: the task moves once to approved, denied, expired or cancelled."""
        ap = self.store.one("SELECT * FROM approvals WHERE id=?", task_id)
        intent = self.bank.payments.by_approval(ap["grant_id"], task_id) if ap else None
        if not ap or not intent:
            raise KeyError(task_id)
        status = ap["status"]
        if status == "pending" and ap["expires"] < time.time():
            status = "expired"
        if status in ("denied", "expired", "cancelled") and intent["status"] == "approval_required":
            # The customer said no, or never answered: release the hold.
            grant = self.store.grant(intent["grant_id"])
            intent = self.bank.payments.cancel(intent, grant, {"denied": "declined by the customer",
                                                               "expired": "the approval request expired"}.get(
                                                                   status, "cancelled"))
        task = {"id": task_id, "status": status, "status_endpoint": f"{self.base}/access/v1/access_requests/{task_id}",
                "expires_at": int(ap["expires"]), "valet": {"reservation": intent["id"]}}
        if status == "pending":
            task["retry_after"] = self.bank.cfg.ciba_interval
        return task

    # ================================================================ reservations (Valet extension)
    def reservation(self, rid: str) -> dict[str, Any]:
        intent = self.bank.payments.get(rid)
        if not intent:
            raise KeyError(rid)
        d = intent["detail"]
        view = {**self._reservation_ref(intent), "state": STATE[intent["status"]], "amount": to_str(intent["amount"]),
                "currency": d["amount"]["currency"], "from_account": d["from"],
                "to": {"name": d["to"]["name"], "account": d["to"]["account"]}, "reference": d.get("reference", ""),
                "approval": intent["approval"], "bank_payment_id": intent["bank_payment_id"],
                # inside the bank's boundary: what its payment system needs to execute the instruction
                "customer": self.store.one("SELECT customer FROM grants WHERE id=?", intent["grant_id"])["customer"],
                "agent": intent["client_id"], "mandate": intent["grant_id"]}
        if intent["status"] in ("failed", "cancelled"):
            view["release_reason"] = "cancelled" if intent["status"] == "cancelled" else (intent["reason"] or "declined")
        if intent["status"] == "cancelling":
            view["cancelling"] = True
        rec = (intent["outcome"] or {}).get("body", {}).get("receipt")
        if rec:
            view["receipt"] = rec
        return view

    def _intent_and_grant(self, rid: str) -> tuple[dict[str, Any], dict[str, Any]]:
        intent = self.bank.payments.get(rid)
        if not intent:
            raise KeyError(rid)
        return intent, self.store.grant(intent["grant_id"])

    def sent(self, rid: str) -> dict[str, Any]:
        """reserved -> sent. `claimed` says whether this caller may hand the payment to the payment system."""
        intent, grant = self._intent_and_grant(rid)
        if intent["status"] in ("confirmed", "failed", "cancelled", "approval_required"):
            if intent["status"] == "approval_required":
                raise Conflict("this reservation still needs the customer's approval")
            out = self.reservation(rid) | {"claimed": False}
        else:
            _, claimed = self.bank.payments.mark_sent(intent, grant)
            out = self.reservation(rid) | {"claimed": claimed}
        self._remember("sent", {"reservation": rid}, out)
        return out

    def commit(self, rid: str, bank_payment_id: str) -> dict[str, Any]:
        intent, grant = self._intent_and_grant(rid)
        if intent["status"] in ("failed", "cancelled"):
            raise Conflict("this reservation was released")
        if intent["status"] == "approval_required":
            raise Conflict("this reservation still needs the customer's approval")
        first = intent["status"] != "confirmed"
        if first:
            self.bank.payments.commit(intent, grant, bank_payment_id)
        out = self.reservation(rid) | {"first": first}
        self._remember("commit", {"reservation": rid, "bank_payment_id": bank_payment_id}, out)
        return out

    def release(self, rid: str, reason: str) -> dict[str, Any]:
        intent, grant = self._intent_and_grant(rid)
        if intent["status"] == "confirmed":
            raise Conflict("this reservation was committed")
        if intent["status"] not in ("failed", "cancelled"):
            self.bank.payments.release(intent, grant, reason or "declined")
        out = self.reservation(rid)
        self._remember("release", {"reservation": rid, "reason": reason}, out)
        return out

    def unknown(self, rid: str, why: str = "") -> dict[str, Any]:
        intent, grant = self._intent_and_grant(rid)
        if intent["status"] == "executing":
            self.bank.payments.report_unknown(intent, grant, why)
        out = self.reservation(rid)
        self._remember("unknown", {"reservation": rid}, out)
        return out

    # ================================================================ helpers
    def _binding(self, intent_id: str) -> str:
        """The AARP binding token for a held payment: derived, so a retry gets the same one; stored only as a hash."""
        return hmac.new(self._binding_key, intent_id.encode(), hashlib.sha256).hexdigest()[:43]

    def _reservation_ref(self, intent: dict[str, Any]) -> dict[str, Any]:
        return {"reservation": intent["id"], "expires_at": int(intent["expires"] or 0),
                "endpoint": f"{self.base}/valet/v1/reservations/{intent['id']}"}

    @staticmethod
    def _summary(detail: dict[str, Any]) -> dict[str, Any]:
        return {"to": detail["to"]["name"], "account": detail["to"]["account"], "amount": detail["amount"]["amount"],
                "currency": detail["amount"]["currency"], "reference": detail.get("reference", "")}

    def _agent_name(self, client_id: str) -> str:
        known = getattr(self.bank, "known_assistants", None)
        name = known.display_name(client_id) if known else None
        if name:
            return name
        rec = self.bank.registry.lookup(client_id)
        return rec.name if rec else client_id

    def _receipt(self, grant: dict[str, Any], action: str, ctx: dict[str, Any], outcome: str, reason: str | None,
                 codes: list[str] | None = None, **kw: Any) -> dict[str, Any]:
        """Receipts keep the MCP channel's action names and reason codes, which the bank app reads."""
        channel = ctx.get("channel", "mcp")
        fields: dict[str, Any] = {"grant_id": grant["id"], "agent": grant["client_id"], "customer": grant["customer"],
                                  "action": f"mcp:{action}" if channel == "mcp" else action, "outcome": outcome,
                                  "basis": "mcp_gateway" if channel == "mcp" else "api",
                                  "reason_codes": codes if codes is not None else ([MCP_CODES.get(reason, reason.upper())]
                                                                                   if reason else []),
                                  "decided_by": "valet_decision_service"}
        if reason:
            fields["reason"] = reason
        if ctx.get("act"):
            fields["act"] = ctx["act"]                    # RFC 8693: the agent acting for the customer
        v = ctx.get("veridact") or {}
        if v:                                            # what Veridact said when the decision was made
            fields["veridact"] = {k: v.get(k) for k in ("entry", "operator", "status", "max_level") if v.get(k)}
        if "tier" not in kw and ctx.get("token_tier"):
            kw["tier"] = ctx["token_tier"]
        return self.bank.receipts.append(**fields, **kw)

    def _remember(self, call: str, req: dict[str, Any], out: dict[str, Any]) -> None:
        with self._log_lock:
            self.log.appendleft({"at": time.strftime("%H:%M:%S"), "call": call, "request": req, "response": out})
