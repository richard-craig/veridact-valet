"""
A deliberately small OpenID Connect provider and authorisation server for tests. Not for real use.

It stands in for the bank's IdP (Auth0, Keycloak, Entra ID, Okta, Ping...) in two roles:
  - customer sign-in over OIDC (authorization code + PKCE, RS256 ID tokens), for federated mode
  - issuing DPoP-bound, RAR-carrying access tokens, for native mode
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse


@dataclass
class MockIdP:
    issuer: str = "http://idp.test"
    client_id: str = "marula-bank"
    client_secret: str = "s3cret"
    user: dict[str, Any] = field(default_factory=lambda: {"sub": "u-123", "preferred_username": "thandi",
                                                          "email": "Thandi@Example.com"})
    auth_age: int = 0                 # seconds since the user "last signed in" (ignores max_age if > 0)
    tamper: str = ""                  # "aud" or "nonce": issue a bad ID token
    kid: str = "idp-rsa-1"

    def __post_init__(self) -> None:
        self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.private.public_key()))
        self.jwk = {**jwk, "kid": self.kid, "use": "sig", "alg": "RS256"}
        self.codes: dict[str, dict[str, Any]] = {}
        self.last_authorize: dict[str, str] = {}
        self.app = self._build()

    @property
    def jwks(self) -> dict[str, Any]:
        return {"keys": [self.jwk]}

    def sign(self, claims: dict[str, Any], typ: str = "JWT") -> str:
        return jwt.encode(claims, self.private, algorithm="RS256", headers={"kid": self.kid, "typ": typ})

    # Native mode: the bank's authorisation server issues the agent's token.
    def access_token(self, *, client_id: str, grant_id: str, jkt: str, details: list[dict[str, Any]],
                     audience: str = "marula-api", ttl: int = 300, jti: str | None = None,
                     grant_claim: str = "valet_grant") -> str:
        now = int(time.time())
        return self.sign({"iss": self.issuer, "aud": audience, "sub": "pairwise-sub", "client_id": client_id,
                          grant_claim: grant_id, "authorization_details": details, "cnf": {"jkt": jkt},
                          "iat": now, "exp": now + ttl, "jti": jti or secrets.token_urlsafe(12)}, typ="at+jwt")

    def _build(self) -> FastAPI:
        app = FastAPI()
        idp = self

        @app.get("/.well-known/openid-configuration")
        def meta():
            return {"issuer": idp.issuer, "authorization_endpoint": idp.issuer + "/authorize",
                    "token_endpoint": idp.issuer + "/token", "jwks_uri": idp.issuer + "/jwks",
                    "id_token_signing_alg_values_supported": ["RS256"]}

        @app.get("/jwks")
        def jwks():
            return idp.jwks

        @app.get("/authorize")
        def authorize(request: Request):
            q = dict(request.query_params)
            idp.last_authorize = q
            if q.get("client_id") != idp.client_id:
                return JSONResponse({"error": "unauthorized_client"}, 400)
            fresh = q.get("max_age") == "0" and idp.auth_age == 0
            code = secrets.token_urlsafe(16)
            idp.codes[code] = {**q, "auth_time": int(time.time()) - (0 if fresh else idp.auth_age)}
            return RedirectResponse(q["redirect_uri"] + "?" + urlencode({"code": code, "state": q.get("state", "")}), 303)

        @app.post("/token")
        def token(request: Request, grant_type: str = Form(...), code: str = Form(""), redirect_uri: str = Form(""),
                  code_verifier: str = Form("")):
            basic = request.headers.get("authorization", "")
            want = "Basic " + base64.b64encode(f"{idp.client_id}:{idp.client_secret}".encode()).decode()
            if basic != want:
                return JSONResponse({"error": "invalid_client"}, 401)
            c = idp.codes.pop(code, None)
            if grant_type != "authorization_code" or not c or c["redirect_uri"] != redirect_uri:
                return JSONResponse({"error": "invalid_grant"}, 400)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=").decode()
            if challenge != c["code_challenge"]:
                return JSONResponse({"error": "invalid_grant", "error_description": "PKCE"}, 400)
            now = int(time.time())
            claims = {"iss": idp.issuer, "aud": idp.client_id, "iat": now, "exp": now + 300,
                      "nonce": c.get("nonce"), "auth_time": c["auth_time"], **idp.user}
            if idp.tamper == "aud":
                claims["aud"] = "someone-else"
            if idp.tamper == "nonce":
                claims["nonce"] = "not-yours"
            return {"access_token": "opaque", "token_type": "Bearer", "id_token": idp.sign(claims)}

        return app
