"""
The Valet agent SDK: what an agent maker integrates once to work with every Valet bank.

    client = ValetClient("kaya", key, bank_url="https://bank.example", redirect_uri="https://kaya.example/callback")
    url, pending = await client.start_connect(level="bill_payer")   # send the customer to `url`
    await client.finish_connect(code, pending)                       # after the bank redirects back
    result = await client.pay(...)                                   # paid, or approval_pending
    result = await client.check_approval(result["auth_req_id"])      # paid once the customer approves

The customer's password, PIN and OTP never pass through this code.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt

from ..common.crypto import Key, b64u, random_id
from ..common.dpop import make_proof

JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
CIBA_GRANT = "urn:openid:params:grant-type:ciba"


class ValetError(Exception):
    def __init__(self, status: int, body: dict[str, Any]):
        self.status, self.body = status, body
        self.error = body.get("error", "error")
        super().__init__(f"{status} {self.error}: {body.get('error_description', '')}")


@dataclass
class PendingConnect:
    state: str
    verifier: str


@dataclass
class Session:
    access_token: str | None = None
    refresh_token: str | None = None
    grant_id: str | None = None
    details: list[dict[str, Any]] = field(default_factory=list)
    expires_at: float = 0


@dataclass
class ConnectServer:
    """The bank's own authorisation server, when it (not Valet) issues the agent's tokens (native mode)."""
    issuer: str
    par: str
    authorize: str
    token: str

    @classmethod
    def from_metadata(cls, meta: dict[str, Any]) -> "ConnectServer":
        return cls(meta["issuer"], meta["pushed_authorization_request_endpoint"], meta["authorization_endpoint"],
                   meta["token_endpoint"])


class ValetClient:
    def __init__(self, client_id: str, key: Key, bank_url: str, redirect_uri: str, issuer: str | None = None,
                 public_bank_url: str | None = None, http: httpx.AsyncClient | None = None,
                 connect_via: ConnectServer | None = None):
        self.client_id, self.key = client_id, key
        self.connect_via = connect_via        # None: Valet's authorisation server (federated mode)
        self.bank_url = bank_url.rstrip("/")                  # where this agent's server reaches the bank
        self.public_bank_url = (public_bank_url or bank_url).rstrip("/")   # where the customer's browser reaches it
        self.issuer = issuer or self.public_bank_url
        self.redirect_uri = redirect_uri
        self.http = http or httpx.AsyncClient(timeout=10)
        self.session = Session()
        self.approvals: dict[str, dict[str, Any]] = {}      # auth_req_id -> the exact payment

    # ------------------------------------------------------------ helpers
    def _assertion(self, audience: str | None = None) -> dict[str, str]:
        now = int(time.time())
        jwt_ = self.key.sign({"iss": self.client_id, "sub": self.client_id, "aud": audience or self.issuer, "iat": now,
                              "exp": now + 60, "jti": random_id("ca")}, headers={"kid": self.key.thumbprint})
        return {"client_id": self.client_id, "client_assertion_type": JWT_BEARER, "client_assertion": jwt_}

    async def _post(self, url: str, data: dict[str, Any], dpop: bool = False, audience: str | None = None) -> dict[str, Any]:
        headers = {"DPoP": make_proof(self.key, "POST", url)} if dpop else {}
        r = await self.http.post(url, data={**data, **self._assertion(audience)}, headers=headers)
        try:
            body = r.json()
        except ValueError:
            body = {"error": "server_error", "error_description": r.text[:200]}
        if r.status_code >= 400:
            raise ValetError(r.status_code, body)
        return body

    async def _post_form(self, path: str, data: dict[str, Any], dpop: bool = False) -> dict[str, Any]:
        return await self._post(self.bank_url + path, data, dpop)

    async def _token_request(self, data: dict[str, Any]) -> dict[str, Any]:
        """Connect and refresh go to whichever server issues the agent's tokens."""
        if self.connect_via:
            return await self._post(self.connect_via.token, data, dpop=True, audience=self.connect_via.issuer)
        return await self._post_form("/token", data, dpop=True)

    def _store_tokens(self, body: dict[str, Any]) -> None:
        grant_id = body.get("grant_id")
        if not grant_id:      # native mode: the bank's IdP carries the Valet grant id in the token (valet_grant)
            grant_id = jwt.decode(body["access_token"], options={"verify_signature": False}).get("valet_grant")
        self.session = Session(body["access_token"], body.get("refresh_token"), grant_id,
                               body.get("authorization_details", []), time.time() + body.get("expires_in", 300) - 15)

    # ------------------------------------------------------------ connect
    async def start_connect(self, level: str = "bill_payer", account_hint: str | None = None) -> tuple[str, PendingConnect]:
        """Push the request (PAR) and return the URL to send the customer to."""
        verifier = b64u(secrets.token_bytes(32))
        challenge = b64u(hashlib.sha256(verifier.encode()).digest())
        details = [{"type": "valet_accounts", "actions": ["read_balances", "read_transactions"]}]
        if level == "bill_payer":
            details.append({"type": "valet_payments", "actions": ["pay_existing_beneficiary"]})
        state = secrets.token_urlsafe(16)
        req = {"response_type": "code", "redirect_uri": self.redirect_uri, "state": state,
               "code_challenge": challenge, "code_challenge_method": "S256"}
        if self.connect_via:
            # The bank's IdP may not support RAR (Keycloak does not): ask for the level; Valet's consent screen,
            # reached through the IdP, builds the exact permission from the customer's choice.
            body = await self._post(self.connect_via.par, {**req, "scope": "openid", "valet_level": level},
                                    audience=self.connect_via.issuer)
            base = self.connect_via.authorize
        else:
            body = await self._post_form("/par", {**req, "authorization_details": json.dumps(details)})
            base = self.public_bank_url + "/authorize"
        url = base + "?" + urlencode({"client_id": self.client_id, "request_uri": body["request_uri"]})
        return url, PendingConnect(state, verifier)

    async def finish_connect(self, code: str, pending: PendingConnect, state: str | None = None) -> Session:
        if state is not None and state != pending.state:
            raise ValetError(400, {"error": "invalid_state", "error_description": "state does not match"})
        body = await self._token_request({"grant_type": "authorization_code", "code": code,
                                          "redirect_uri": self.redirect_uri, "code_verifier": pending.verifier})
        self._store_tokens(body)
        return self.session

    async def refresh(self) -> None:
        body = await self._token_request({"grant_type": "refresh_token", "refresh_token": self.session.refresh_token})
        self._store_tokens(body)

    # ------------------------------------------------------------ calling the bank API
    async def call(self, method: str, path: str, json_body: Any = None, token: str | None = None) -> dict[str, Any]:
        if token is None and self.session.access_token and time.time() > self.session.expires_at and self.session.refresh_token:
            await self.refresh()
        tok = token or self.session.access_token
        if not tok:
            raise ValetError(401, {"error": "not_connected", "error_description": "connect to the bank first"})
        url = self.bank_url + path
        headers = {"Authorization": f"DPoP {tok}", "DPoP": make_proof(self.key, method, url, access_token=tok)}
        r = await self.http.request(method, url, json=json_body, headers=headers)
        body = r.json()
        if r.status_code >= 400:
            raise ValetError(r.status_code, body)
        return body

    async def accounts(self) -> list[dict[str, Any]]:
        return (await self.call("GET", "/api/accounts"))["accounts"]

    # ------------------------------------------------------------ payments and approvals
    async def pay(self, from_account: str, to_name: str, to_account: str, amount: str, reference: str = "",
                  note: str = "") -> dict[str, Any]:
        """Pay inside the grant, or start an approval if the bank asks for one."""
        payment = {"from_account": from_account, "to": {"name": to_name, "account": to_account}, "amount": amount,
                   "reference": reference}
        try:
            return {"outcome": "paid", **await self.call("POST", "/api/payments", payment)}
        except ValetError as e:
            if e.error != "approval_required":
                raise
            detail = e.body["authorization_details"]
            body = await self._post_form("/bc-authorize", {"login_hint": self.session.grant_id,
                                                           "authorization_details": json.dumps(detail),
                                                           "binding_message": note or f"Pay {to_name} {amount}"})
            self.approvals[body["auth_req_id"]] = payment
            return {"outcome": "approval_pending", "auth_req_id": body["auth_req_id"], "reason": e.body.get("error_description"),
                    "expires_in": body["expires_in"], "interval": body["interval"]}

    async def check_approval(self, auth_req_id: str) -> dict[str, Any]:
        """Poll once. Returns pending, denied, expired, or the completed payment."""
        try:
            body = await self._post_form("/token", {"grant_type": CIBA_GRANT, "auth_req_id": auth_req_id}, dpop=True)
        except ValetError as e:
            if e.error in ("authorization_pending", "slow_down"):
                return {"outcome": "approval_pending", "auth_req_id": auth_req_id}
            if e.error == "access_denied":
                return {"outcome": "declined", "auth_req_id": auth_req_id}
            if e.error == "expired_token":
                return {"outcome": "expired", "auth_req_id": auth_req_id}
            raise
        once_token = body["access_token"]
        result = await self.call("POST", "/api/payments", self.approvals[auth_req_id], token=once_token)
        return {"outcome": "paid", "approved": True, "once_token": once_token, **result}
