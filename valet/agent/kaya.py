"""
Kaya (fictional): a tiny money assistant web app that uses the Valet SDK.
It never asks for, sees or stores the customer's banking password, PIN or OTP.
"""
from __future__ import annotations

import os
from pathlib import Path
from decimal import Decimal
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..bank.registry import publish_agent_key
from ..common.crypto import Key
from .sdk import ConnectServer, PendingConnect, ValetClient, ValetError

def R(amount: str) -> str:
    """'1250.00' -> 'R1,250.00'"""
    return f"R{Decimal(str(amount)):,.2f}"


_env = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"), autoescape=select_autoescape())

# Thandi's bills, as Kaya knows them. Kaya's actions in the demo.
ACTIONS = {
    "water": {"label": "Pay the water bill · R640", "to": ("Water & Sanitation", "40021187"), "amount": "640.00",
              "reference": "Water Oct", "note": "Monthly water bill"},
    "power": {"label": "Pay City Power · R1,250 (new recipient)", "to": ("City Power", "30087712"), "amount": "1250.00",
              "reference": "Electricity Oct", "note": "Your electricity account is due on Friday"},
    "school": {"label": "Pay school fees · R1,500 (over the monthly limit)", "to": ("Sunrise Primary School", "62114930"),
               "amount": "1500.00", "reference": "Term 4", "note": "Term 4 school fees"},
}


def create_kaya_app(bank_url: str | None = None, public_bank_url: str | None = None, public_url: str | None = None,
                    data_dir: Path | None = None, http: httpx.AsyncClient | None = None, issuer: str | None = None) -> FastAPI:
    bank_url = bank_url or os.environ.get("BANK_INTERNAL_URL", "http://localhost:8000")
    public_bank_url = public_bank_url or os.environ.get("BANK_PUBLIC_URL", bank_url)
    public_url = (public_url or os.environ.get("KAYA_PUBLIC_URL", "http://localhost:8001")).rstrip("/")
    data_dir = data_dir or Path(os.environ.get("VALET_DATA", "./data"))
    key = Key.load_or_create(data_dir / "kaya" / "agent-key.pem")   # demo only: production keys live in KMS or a TPM
    redirect_uri = public_url + "/callback"
    publish_agent_key(data_dir, "kaya", key.jwk, [redirect_uri])   # stands in for registration with the bank / Veridact

    # Native mode: connect through the bank's own authorisation server, e.g.
    # KAYA_CONNECT_VIA=http://localhost:8080/realms/marula/.well-known/openid-configuration
    connect_via = None
    if os.environ.get("KAYA_CONNECT_VIA"):
        connect_via = ConnectServer.from_metadata(httpx.get(os.environ["KAYA_CONNECT_VIA"], timeout=10).json())
    client = ValetClient("kaya", key, bank_url, redirect_uri, issuer=issuer or public_bank_url,
                         public_bank_url=public_bank_url, http=http, connect_via=connect_via)
    app = FastAPI(title="Kaya (Veridact Valet PoC agent)")
    state: dict[str, Any] = {"pending": None, "log": [], "approval": None}
    app.state.client = client

    def page(**ctx: Any) -> HTMLResponse:
        return HTMLResponse(_env.get_template("kaya.html").render(connected=bool(client.session.access_token),
                                                                  actions=ACTIONS, log=state["log"][-10:],
                                                                  approval=state["approval"], bank_url=public_bank_url, **ctx))

    def say(who: str, text: str, kind: str = "") -> None:
        state["log"].append({"who": who, "text": text, "kind": kind})

    @app.get("/", response_class=HTMLResponse)
    def home():
        return page()

    @app.post("/connect")
    async def connect():
        url, pending = await client.start_connect("bill_payer")
        state["pending"] = pending
        return RedirectResponse(url, 303)

    @app.get("/callback")
    async def callback(request: Request, code: str = "", error: str = ""):
        st = request.query_params.get("state", "")
        if error:
            say("kaya", "No problem, I won't connect. You can try again any time.")
            return RedirectResponse("/", 303)
        pending: PendingConnect | None = state["pending"]
        if not pending or not code:
            say("kaya", "That connection link has expired or didn't start here. Please try connecting again.", "blocked")
            return RedirectResponse("/", 303)
        state["pending"] = None                                   # one use
        try:
            await client.finish_connect(code, pending, st)
        except ValetError as e:
            say("kaya", f"The bank didn't complete the connection ({e.error}). Please try again.", "blocked")
            return RedirectResponse("/", 303)
        details = client.session.details
        lvl = (" as Bill payer" if any(d["type"] == "valet_payments" for d in details) else " as View only") if details else ""
        say("kaya", f"Connected to Marula Bank{lvl}. I never saw your password.", "ok")
        return RedirectResponse("/", 303)

    @app.post("/do/{what}")
    async def do(what: str):
        try:
            if what == "balance":
                accts = await client.accounts()
                say("kaya", "Your balances: " + ", ".join(f"{a['name']} {R(a['balance'])}" for a in accts), "ok")
            elif what == "beneficiary":
                say("you", "Add QuickLoans as a beneficiary")
                await client.call("POST", "/api/beneficiaries", {"name": "QuickLoans", "account": "99887766"})
            elif what in ACTIONS:
                a = ACTIONS[what]
                say("you", a["label"])
                res = await client.pay("acc_4821", a["to"][0], a["to"][1], a["amount"], a["reference"], a["note"])
                if res["outcome"] == "paid":
                    say("kaya", f"Paid {res['to']} {R(res['amount'])}. This month: {R(res['spent_this_month'])} of {R(res['monthly_limit'])}.", "ok")
                else:
                    state["approval"] = res["auth_req_id"]
                    say("kaya", f"Marula asked you to approve this first ({res['reason']}). Check your Marula app.", "held")
        except ValetError as e:
            say("kaya", f"Marula said no: {e.body.get('error_description', e.error)}", "blocked")
        return RedirectResponse("/", 303)

    @app.get("/approval", response_class=HTMLResponse)
    async def approval():
        aid = state["approval"]
        if aid:
            try:
                res = await client.check_approval(aid)
            except ValetError as e:
                res = {"outcome": "error", "detail": e.body.get("error_description", e.error)}
            if res["outcome"] == "paid":
                say("kaya", f"You approved it. Paid {res['to']} {R(res['amount'])}, once.", "ok")
                state["approval"] = None
            elif res["outcome"] in ("declined", "expired", "error"):
                say("kaya", f"The payment was {res['outcome']}. I haven't paid anything.", "blocked")
                state["approval"] = None
        return RedirectResponse("/", 303)

    return app


def get_app() -> FastAPI:
    return create_kaya_app()
