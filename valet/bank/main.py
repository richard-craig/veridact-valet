"""Marula Bank (fictional): authorisation server + API + customer app, in one FastAPI service."""
from __future__ import annotations

from fastapi import FastAPI, Request

from . import api, authz, grants, handoff, web
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

    app.include_router(authz.router(bank))
    app.include_router(api.router(bank))
    app.include_router(web.router(bank))
    app.include_router(grants.router(bank))
    app.include_router(handoff.router(bank))
    return app


app = None


def get_app() -> FastAPI:
    """Uvicorn factory: `uvicorn valet.bank.main:get_app --factory`."""
    return create_app()
