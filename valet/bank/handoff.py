"""
Consent hand-off: the bank's IdP signs the customer in, Valet shows the consent screen (native mode).

    agent --PAR--> bank IdP --signs customer in--> Valet /handoff/consent?ticket=...   (ticket signed by the IdP)
          customer chooses on the bank's consent screen; Valet registers the grant under the bank's policy
    Valet --auto-POST valet_result=...--> IdP (back into the same login)               (result signed by Valet)
    IdP issues the agent's DPoP-bound token with valet_grant=<grant id>

Why hand off rather than let the IdP draw its own consent screen: every IdP then shows the same screen, the customer
can choose less than the agent asked for (Auth0 Actions, for one, cannot change authorization_details), and the
grant is created where its rules live.

The Keycloak side is extensions/keycloak-valet. Both directions use HS256 with VALET_HANDOFF_SECRET in the PoC;
a bank would use asymmetric keys (each side verifying the other via JWKS).
"""
from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlparse

import jwt
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from ..common.money import rand
from . import levels as L
from .context import Bank
from .grants import create_grant
from .web import render

HANDOFF_ALG = "HS256"


class HandoffError(Exception):
    pass


def router(bank: Bank) -> APIRouter:
    r = APIRouter(prefix="/handoff")
    cfg, store = bank.cfg, bank.store

    def read_ticket(ticket: str) -> dict[str, Any]:
        if not cfg.handoff_secret:
            raise HandoffError("Consent hand-off is not enabled at this bank.")
        try:
            t = jwt.decode(ticket or "", cfg.handoff_secret, algorithms=[HANDOFF_ALG], audience=cfg.issuer,
                           options={"require": ["exp", "iat", "iss", "nonce", "customer", "client_id", "return_to"]})
        except jwt.PyJWTError as e:
            raise HandoffError("This request has expired or was not issued by the bank's sign-in service.") from e
        if t["iss"] not in cfg.handoff_idps:
            raise HandoffError("This sign-in service is not allowed to hand customers to Valet.")
        allowed = cfg.handoff_idps[t["iss"]]
        if not t["return_to"].startswith(allowed):        # never post a result anywhere but the bank's own IdP
            raise HandoffError("This request asks to return somewhere the bank does not allow.")
        if urlparse(t["return_to"]).scheme not in ("https", "http"):
            raise HandoffError("Invalid return address.")
        return t

    def context(t: dict[str, Any]) -> tuple[dict[str, Any], Any]:
        cus = store.customer_for_idp(str(t.get("email") or "")) or store.customer_for_idp(str(t["customer"]))
        if not cus:
            raise HandoffError("You signed in, but no Marula Bank customer matches that identity.")
        agent = bank.registry.lookup(t["client_id"])
        if not agent or not bank.registry.is_trusted(agent.client_id):
            raise HandoffError("This assistant is not verified, so the bank will not connect it.")
        return dict(cus), agent

    def error_page(request: Request, msg: str) -> HTMLResponse:
        return render(request, "signin_error.html", bank, status=400, error=msg)

    @r.get("/consent", response_class=HTMLResponse)
    def consent(request: Request, ticket: str = ""):
        try:
            t = read_ticket(ticket)
            cus, agent = context(t)
        except HandoffError as e:
            return error_page(request, str(e))
        level = t.get("requested_level") if t.get("requested_level") in L.LEVELS else "view_only"
        accounts = store.q("SELECT * FROM accounts WHERE customer=?", cus["id"])
        return render(request, "consent.html", bank, customer=cus, agent=agent, client_id=agent.client_id,
                      action="/handoff/decision", hidden={"ticket": ticket}, preselect=level, levels=L.LEVELS,
                      accounts=accounts, days=cfg.max_grant_days,
                      monthly_choices=[(c, rand(c)) for c in L.MONTHLY_CHOICES if c <= cfg.max_monthly_limit])

    @r.post("/decision", response_class=HTMLResponse)
    async def decision(request: Request):
        form = await request.form()
        try:
            t = read_ticket(str(form.get("ticket", "")))
            cus, agent = context(t)
        except HandoffError as e:
            return error_page(request, str(e))
        # The ticket is single use: a replayed form cannot create a second grant.
        if store.seen_jti("handoff:" + t["nonce"], ttl=max(60, t["exp"] - time.time() + 60)):
            return error_page(request, "This request has already been answered.")
        now = int(time.time())
        result: dict[str, Any] = {"iss": cfg.issuer, "aud": t["iss"], "iat": now, "exp": now + 120, "nonce": t["nonce"]}
        if form.get("decision") == "allow":
            try:
                g = create_grant(bank, cus, agent, str(form.get("level", "view_only")), str(form.get("account", "")),
                                 int(form.get("monthly") or 2_000_00), via="bank identity provider (consent hand-off)")
            except ValueError as e:
                return error_page(request, f"That choice isn't possible: {e}.")
            result |= {"decision": "allow", "grant_id": g["id"]}
        else:
            result |= {"decision": "deny"}
        token = jwt.encode(result, cfg.handoff_secret, algorithm=HANDOFF_ALG)
        return render(request, "handoff_return.html", bank, return_to=t["return_to"], result=token,
                      allowed=result["decision"] == "allow")

    return r
