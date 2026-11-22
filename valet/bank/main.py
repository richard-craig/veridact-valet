"""Marula Bank (fictional): authorisation server + API + customer app, in one FastAPI service."""
from __future__ import annotations

from fastapi import FastAPI, Request

import os

from ..decision import api as decision_api
from ..decision.client import from_env as decisions_from_env
from ..decision.service import DecisionService
from . import api, authz, consents, grants, handoff, mcp, openbanking, web
from .config import BankConfig
from .context import Bank, OAuthError
from .registry import DEFAULT_TRUST, write_trust_file


def create_app(cfg: BankConfig | None = None, bank: Bank | None = None) -> FastAPI:
    cfg = cfg or BankConfig()
    if not (cfg.data_dir / "trust.json").exists():
        write_trust_file(cfg.data_dir, DEFAULT_TRUST)
    bank = bank or Bank(cfg)
    app = FastAPI(title="Marula Bank (Veridact Valet PoC)", docs_url="/docs")
    app.state.bank = bank

    @app.exception_handler(OAuthError)
    async def oauth_error(_: Request, e: OAuthError):
        return e.response()

    @app.get("/readyz")
    def readyz():
        """Deployment checks assert on this: key binding mode, payments adapter, registry, denylist, ops queue."""
        return bank.readiness()

    @app.exception_handler(consents.Problem)
    async def problem(request: Request, e: consents.Problem):
        return e.response(request)

    svc = bank.consents if getattr(bank, "consents", None) else consents.ConsentService(bank)
    bank.consents = svc

    app.include_router(authz.router(bank))
    app.include_router(api.router(bank))
    app.include_router(web.router(bank))
    app.include_router(grants.router(bank))
    app.include_router(handoff.router(bank))
    consent_api, consent_pages = consents.routers(bank, svc)
    app.include_router(consent_api)
    app.include_router(consent_pages)
    app.include_router(openbanking.router(bank, svc))
    # The Valet decision service (docs/decision-service.md): the bank's MCP server asks it before every action. It is
    # published over HTTP for the bank's enforcement points (VALET_DECISION_SECRET), and reached in-process unless
    # VALET_DECISION_URL points the MCP server at it over the network.
    if getattr(bank, "decision_service", None) is None:
        bank.decision_service = DecisionService(bank)
    if getattr(bank, "decisions", None) is None:
        bank.decisions = decisions_from_env(bank.decision_service)
    app.include_router(decision_api.router(bank.decision_service, os.environ.get("VALET_DECISION_SECRET", "")))
    app.include_router(mcp.router(bank))
    return app


app = None


def get_app() -> FastAPI:
    """Uvicorn factory: `uvicorn valet.bank.main:get_app --factory`."""
    return create_app()
