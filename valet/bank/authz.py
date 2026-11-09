"""
The authorisation server: PAR, the consent screen, the token endpoint (authorization code,
refresh, CIBA) and the CIBA backchannel endpoint.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from ..common.crypto import b64u, digest, random_id, sha256_b64u
from ..common.dpop import DPoPError, check_proof
from ..common.money import rand, to_cents
from . import levels as L
from .context import Bank, OAuthError
from .grants import create_grant
from .web import current_customer, csrf_ok, csrf_token, needs_step_up, render, step_up

KNOWN_TYPES = {"valet_accounts", "valet_payments"}
CIBA_GRANT = "urn:openid:params:grant-type:ciba"


def _form(request_form) -> dict[str, Any]:
    return {k: v for k, v in request_form.items()}


def router(bank: Bank) -> APIRouter:
    r = APIRouter()
    cfg, store = bank.cfg, bank.store

    def dpop_jkt(request: Request) -> str:
        try:
            return check_proof(request.headers.get("DPoP"), request.method, str(request.url), store.seen_jti)
        except DPoPError as e:
            raise OAuthError("invalid_dpop_proof", str(e), 400) from e

    # ------------------------------------------------------------ metadata
    @r.get("/.well-known/oauth-authorization-server")
    def metadata():
        i = cfg.issuer
        return {"issuer": i, "pushed_authorization_request_endpoint": f"{i}/par", "authorization_endpoint": f"{i}/authorize",
                "token_endpoint": f"{i}/token", "backchannel_authentication_endpoint": f"{i}/bc-authorize",
                "jwks_uri": f"{i}/jwks", "require_pushed_authorization_requests": True,
                "token_endpoint_auth_methods_supported": ["private_key_jwt"], "dpop_signing_alg_values_supported": ["ES256"],
                "authorization_details_types_supported": ["valet_accounts", "valet_payments", "valet_payment_once"],
                "backchannel_token_delivery_modes_supported": ["poll"], "code_challenge_methods_supported": ["S256"],
                "grant_types_supported": ["authorization_code", "refresh_token", CIBA_GRANT]}

    @r.get("/jwks")
    def jwks():
        return {"keys": [{**bank.as_key.jwk, "kid": "as-1", "use": "sig", "alg": "ES256"},
                         {**bank.receipt_key.jwk, "kid": "receipts-1", "use": "sig", "alg": "ES256"}]}

    # ----------------------------------------------------------------- PAR
    @r.post("/par", status_code=201)
    async def par(request: Request):
        try:
            form = _form(await request.form())
            rec = bank.authenticate_client(form)
            if form.get("response_type") != "code":
                raise OAuthError("unsupported_response_type", "response_type must be code")
            if form.get("redirect_uri") not in rec.redirect_uris:
                raise OAuthError("invalid_request", "redirect_uri is not registered for this agent")
            if not form.get("code_challenge") or form.get("code_challenge_method") != "S256":
                raise OAuthError("invalid_request", "PKCE with S256 is required")
            try:
                details = json.loads(form.get("authorization_details") or "[]")
            except json.JSONDecodeError as e:
                raise OAuthError("invalid_authorization_details", "authorization_details is not JSON") from e
            if not isinstance(details, list) or any(d.get("type") not in KNOWN_TYPES for d in details):
                raise OAuthError("invalid_authorization_details", "unknown authorization_details type")
            request_uri = "urn:ietf:params:oauth:request_uri:" + secrets.token_urlsafe(24)
            params = {k: form.get(k) for k in ("redirect_uri", "state", "code_challenge")} | {"details": details}
            store.x("INSERT INTO par VALUES (?,?,?,?,0)", request_uri, rec.client_id, json.dumps(params), time.time() + cfg.par_ttl)
            return JSONResponse({"request_uri": request_uri, "expires_in": cfg.par_ttl}, status_code=201)
        except OAuthError as e:
            return e.response()

    def load_par(client_id: str, request_uri: str) -> dict[str, Any]:
        row = store.one("SELECT * FROM par WHERE request_uri=?", request_uri or "")
        if not row or row["client_id"] != client_id:
            raise OAuthError("invalid_request", "unknown request_uri: requests must be pushed with PAR first")
        if row["used"] or row["expires"] < time.time():
            raise OAuthError("invalid_request", "request_uri has expired or been used")
        return json.loads(row["params"])

    # ------------------------------------------------------------- consent
    @r.get("/authorize", response_class=HTMLResponse)
    def authorize(request: Request, client_id: str = "", request_uri: str = ""):
        try:
            params = load_par(client_id, request_uri)
        except OAuthError as e:
            return HTMLResponse(f"<h1>Request refused</h1><p>{e.description}</p>", status_code=400)
        cus = current_customer(bank, request)
        here = str(request.url.path) + "?" + str(request.url.query)
        if not cus:
            return RedirectResponse("/login?" + urlencode({"next": here}), 303)
        if needs_step_up(bank, cus):
            return step_up(here)
        rec = bank.registry.lookup(client_id)
        accounts = store.q("SELECT * FROM accounts WHERE customer=?", cus["id"])
        return render(request, "consent.html", bank, customer=cus, agent=rec, client_id=client_id, request_uri=request_uri,
                      preselect=L.requested_level(params["details"]), levels=L.LEVELS, accounts=accounts,
                      monthly_choices=[(c, rand(c)) for c in L.MONTHLY_CHOICES if c <= cfg.max_monthly_limit],
                      days=cfg.max_grant_days, csrf=csrf_token(bank, cus["id"]))

    @r.post("/authorize/decision")
    async def decision(request: Request):
        form = _form(await request.form())
        cus = current_customer(bank, request)
        if not cus or not csrf_ok(bank, cus["id"], form.get("csrf", "")):
            return HTMLResponse("<h1>Session expired</h1>", status_code=403)
        if needs_step_up(bank, cus):
            return step_up("/authorize?" + urlencode({"client_id": form.get("client_id", ""),
                                                      "request_uri": form.get("request_uri", "")}))
        try:
            params = load_par(form.get("client_id", ""), form.get("request_uri", ""))
        except OAuthError as e:
            return HTMLResponse(f"<h1>Request refused</h1><p>{e.description}</p>", status_code=400)
        store.x("UPDATE par SET used=1 WHERE request_uri=?", form["request_uri"])
        redirect, state = params["redirect_uri"], params.get("state") or ""
        if form.get("decision") != "allow":
            return RedirectResponse(redirect + "?" + urlencode({"error": "access_denied", "state": state}), 303)
        rec = bank.registry.lookup(form["client_id"])
        try:
            grant = create_grant(bank, cus, rec, form.get("level", "view_only"), form.get("account", ""),
                                 int(form.get("monthly") or 2_000_00), via="Valet consent screen")
        except ValueError:
            return HTMLResponse("<h1>Invalid choice</h1>", status_code=400)
        gid, now = grant["id"], time.time()
        code = secrets.token_urlsafe(24)
        store.x("INSERT INTO codes VALUES (?,?,?,?,?,?,0)", code, gid, rec.client_id, redirect, params["code_challenge"],
                now + cfg.code_ttl)
        return RedirectResponse(redirect + "?" + urlencode({"code": code, "state": state}), 303)

    # --------------------------------------------------------------- token
    @r.post("/token")
    async def token(request: Request):
        try:
            form = _form(await request.form())
            rec = bank.authenticate_client(form)
            gt = form.get("grant_type")
            if gt == "authorization_code":
                return code_grant(request, form, rec)
            if gt == "refresh_token":
                return refresh_grant(request, form, rec)
            if gt == CIBA_GRANT:
                return ciba_grant(request, form, rec)
            raise OAuthError("unsupported_grant_type", f"grant_type {gt!r} is not supported")
        except OAuthError as e:
            return e.response()

    def new_refresh(grant_id: str, jkt: str) -> str:
        rt = "rt_" + secrets.token_urlsafe(32)
        store.x("INSERT INTO refresh VALUES (?,?,?,0,?)", sha256_b64u(rt), grant_id, jkt, time.time())
        return rt

    def token_response(grant: dict[str, Any], jkt: str) -> JSONResponse:
        at = bank.issue_access_token(grant, jkt, grant["details"])
        return JSONResponse({"access_token": at, "token_type": "DPoP", "expires_in": cfg.access_ttl,
                             "refresh_token": new_refresh(grant["id"], jkt), "grant_id": grant["id"],
                             "authorization_details": grant["details"]}, headers={"Cache-Control": "no-store"})

    def code_grant(request: Request, form: dict[str, Any], rec) -> JSONResponse:
        jkt = dpop_jkt(request)
        row = store.one("SELECT * FROM codes WHERE code=?", form.get("code", ""))
        if not row or row["client_id"] != rec.client_id or row["used"] or row["expires"] < time.time():
            raise OAuthError("invalid_grant", "code is invalid, expired or already used")
        if row["redirect_uri"] != form.get("redirect_uri"):
            raise OAuthError("invalid_grant", "redirect_uri does not match")
        if b64u(hashlib.sha256((form.get("code_verifier") or "").encode()).digest()) != row["challenge"]:
            raise OAuthError("invalid_grant", "PKCE code_verifier does not match")
        store.x("UPDATE codes SET used=1 WHERE code=?", row["code"])
        store.x("UPDATE grants SET jkt=? WHERE id=?", jkt, row["grant_id"])
        return token_response(store.grant(row["grant_id"]), jkt)

    def refresh_grant(request: Request, form: dict[str, Any], rec) -> JSONResponse:
        jkt = dpop_jkt(request)
        row = store.one("SELECT * FROM refresh WHERE hash=?", sha256_b64u(form.get("refresh_token") or ""))
        if not row:
            raise OAuthError("invalid_grant", "unknown refresh token")
        grant = store.grant(row["grant_id"])
        if row["used"]:
            # Reuse means a copy exists somewhere else: stop the grant and tell the customer.
            store.set_status(grant["id"], "paused")
            bank.receipts.append(grant_id=grant["id"], agent=grant["client_id"], customer=grant["customer"],
                                 action="refresh", outcome="refused", basis="refused",
                                 reason="refresh token reused; grant paused for safety")
            raise OAuthError("invalid_grant", "refresh token reuse detected; the grant has been paused")
        if row["jkt"] != jkt or grant["client_id"] != rec.client_id:
            raise OAuthError("invalid_grant", "refresh token is bound to a different key or agent")
        if grant["status"] != "active":
            raise OAuthError("invalid_grant", f"grant is {grant['status']}")
        store.x("UPDATE refresh SET used=1 WHERE hash=?", row["hash"])
        return token_response(grant, jkt)

    def ciba_grant(request: Request, form: dict[str, Any], rec) -> JSONResponse:
        jkt = dpop_jkt(request)
        ap = store.one("SELECT * FROM approvals WHERE id=?", form.get("auth_req_id", ""))
        if not ap or ap["client_id"] != rec.client_id:
            raise OAuthError("invalid_grant", "unknown auth_req_id")
        grant = store.grant(ap["grant_id"])
        if grant["jkt"] != jkt:
            raise OAuthError("invalid_grant", "proof key does not match the grant")
        if ap["status"] in ("pending",) and ap["expires"] < time.time():
            store.x("UPDATE approvals SET status='expired' WHERE id=?", ap["id"])
            raise OAuthError("expired_token", "the customer did not respond in time")
        if ap["status"] == "pending":
            raise OAuthError("authorization_pending", "waiting for the customer")
        if ap["status"] in ("denied", "cancelled", "expired"):
            raise OAuthError("access_denied", f"the request was {ap['status']}")
        if ap["token_issued"]:
            raise OAuthError("invalid_grant", "a token was already issued for this approval")
        store.x("UPDATE approvals SET token_issued=1 WHERE id=?", ap["id"])
        detail = json.loads(ap["detail"])
        at = bank.issue_access_token(grant, jkt, [detail], approval=ap["id"], exp=ap["expires"])
        return JSONResponse({"access_token": at, "token_type": "DPoP", "expires_in": int(ap["expires"] - time.time()),
                             "authorization_details": [detail]}, headers={"Cache-Control": "no-store"})

    # ----------------------------------------------------------------- CIBA
    @r.post("/bc-authorize")
    async def bc_authorize(request: Request):
        try:
            form = _form(await request.form())
            rec = bank.authenticate_client(form)
            grant = store.grant(form.get("login_hint", ""))
            if not grant or grant["client_id"] != rec.client_id:
                raise OAuthError("unknown_user_id", "login_hint must be one of this agent's grants")
            if grant["status"] != "active":
                raise OAuthError("access_denied", f"grant is {grant['status']}")
            try:
                details = json.loads(form.get("authorization_details") or "[]")
            except json.JSONDecodeError as e:
                raise OAuthError("invalid_authorization_details", "authorization_details is not JSON") from e
            if len(details) != 1 or details[0].get("type") != "valet_payment_once":
                raise OAuthError("invalid_authorization_details", "exactly one valet_payment_once is required")
            d = digest(details[0])
            hint = store.one("SELECT * FROM hints WHERE grant_id=? AND digest=? AND expires>?", grant["id"], d, time.time())
            if not hint:
                raise OAuthError("invalid_authorization_details",
                                 "this action was not offered for approval by the bank API (or the offer expired)")
            pending = store.one("SELECT COUNT(*) n FROM approvals WHERE grant_id=? AND status='pending' AND expires>?",
                                grant["id"], time.time())["n"]
            if pending >= cfg.max_pending_approvals:
                raise OAuthError("slow_down", "too many approvals already waiting for the customer")
            message = (form.get("binding_message") or "")[:120]
            aid = random_id("ar", 12)
            now = time.time()
            store.x("INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?,?,0,0)", aid, grant["id"], rec.client_id,
                    json.dumps(details[0]), d, message, json.loads(hint["detail"])["_reason"], "pending", now,
                    now + cfg.approval_ttl)
            bank.receipts.append(grant_id=grant["id"], agent=rec.client_id, customer=grant["customer"], action="approval_request",
                                 outcome="pending", basis="approval_required", approval=aid,
                                 detail=_payment_summary(details[0]))
            return JSONResponse({"auth_req_id": aid, "expires_in": cfg.approval_ttl, "interval": cfg.ciba_interval})
        except OAuthError as e:
            return e.response()

    return r


def _payment_summary(detail: dict[str, Any]) -> dict[str, Any]:
    return {"to": detail["to"]["name"], "account": detail["to"]["account"], "amount": detail["amount"]["amount"],
            "currency": detail["amount"]["currency"], "reference": detail.get("reference", "")}


def payment_detail(from_account: str, to_name: str, to_account: str, amount_cents: int, reference: str) -> dict[str, Any]:
    from ..common.money import CURRENCY, to_str
    return {"type": "valet_payment_once", "from": from_account, "to": {"name": to_name, "account": to_account},
            "amount": {"amount": to_str(amount_cents), "currency": CURRENCY}, "reference": reference}


__all__ = ["router", "payment_detail", "to_cents"]
