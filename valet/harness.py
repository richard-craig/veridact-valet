"""
An in-process harness: the bank and an agent wired together over ASGI, plus a scripted
"customer browser". The scripted demo and the tests both drive Valet through this.
"""
from __future__ import annotations

import re
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx

from .agent.sdk import ValetClient
from .bank.config import BankConfig
from .bank.context import Bank
from .bank.main import create_app
from .bank.registry import DEFAULT_TRUST, publish_agent_key, write_trust_file
from .common.crypto import Key

BANK = "http://bank.test"
KAYA_CALLBACK = "http://kaya.test/callback"


class Harness:
    def __init__(self, data_dir: Path | None = None, signin=None, external_issuers=None, internal_secret: str = "",
                 **cfg_overrides):
        self.dir = Path(data_dir or tempfile.mkdtemp(prefix="valet-"))
        write_trust_file(self.dir, DEFAULT_TRUST)
        self.kaya_key, self.copycat_key = Key.generate(), Key.generate()
        publish_agent_key(self.dir, "kaya", self.kaya_key.jwk, [KAYA_CALLBACK])
        publish_agent_key(self.dir, "copycat", self.copycat_key.jwk, [KAYA_CALLBACK])
        self.cfg = BankConfig(issuer=BANK, data_dir=self.dir, db_path=Path(":memory:"), internal_secret=internal_secret,
                              **cfg_overrides)
        self.app = create_app(self.cfg, Bank(self.cfg, signin=signin, external_issuers=external_issuers or {}))
        self.bank = self.app.state.bank
        self.transport = httpx.ASGITransport(app=self.app)
        self.kaya = self.agent("kaya", self.kaya_key)
        self.browser = httpx.AsyncClient(transport=self.transport, base_url=BANK, follow_redirects=False)

    def agent(self, client_id: str, key: Key) -> ValetClient:
        return ValetClient(client_id, key, BANK, KAYA_CALLBACK, issuer=BANK,
                           http=httpx.AsyncClient(transport=self.transport, timeout=10))

    # ------------------------------------------------------------- customer
    async def login(self) -> None:
        r = await self.browser.post("/login", data={"username": "thandi", "password": "demo", "next": "/app"})
        assert r.status_code == 303, r.text

    @staticmethod
    def csrf(html: str) -> str:
        return re.search(r'name="csrf" value="([^"]+)"', html).group(1)

    async def consent(self, authorize_url: str, level: str = "bill_payer", monthly: int = 2_000_00,
                      decision: str = "allow") -> tuple[str, dict[str, list[str]]]:
        """The customer opens the bank's consent screen, chooses, and confirms. Returns the HTML seen and the redirect."""
        u = urlparse(authorize_url)
        page = await self.browser.get(u.path + "?" + u.query)
        assert page.status_code == 200, page.text
        q = parse_qs(u.query)
        r = await self.browser.post("/authorize/decision", data={
            "csrf": self.csrf(page.text), "client_id": q["client_id"][0], "request_uri": q["request_uri"][0],
            "level": level, "monthly": str(monthly), "account": "acc_4821", "decision": decision})
        assert r.status_code == 303, r.text
        return page.text, parse_qs(urlparse(r.headers["location"]).query)

    async def connect(self, level: str = "bill_payer", monthly: int = 2_000_00) -> str:
        await self.login()
        url, pending = await self.kaya.start_connect(level)
        _, back = await self.consent(url, level, monthly)
        await self.kaya.finish_connect(back["code"][0], pending, back["state"][0])
        return self.kaya.session.grant_id

    async def decide(self, auth_req_id: str, approve: bool = True) -> str:
        page = await self.browser.get(f"/app/approvals/{auth_req_id}")
        r = await self.browser.post(f"/app/approvals/{auth_req_id}",
                                    data={"csrf": self.csrf(page.text), "decision": "approve" if approve else "deny"})
        assert r.status_code == 303
        return page.text

    async def grant_action(self, grant_id: str, action: str) -> None:
        page = await self.browser.get(f"/app/agents/{grant_id}")
        r = await self.browser.post(f"/app/agents/{grant_id}/{action}", data={"csrf": self.csrf(page.text)})
        assert r.status_code == 303
