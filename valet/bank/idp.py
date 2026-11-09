"""
Customer sign-in: the bank's identity provider, not Valet, owns the customer's identity.

Valet needs exactly two things from the bank's IdP:
  1. who the customer is (a claim it can map to a bank customer), and
  2. that they signed in recently enough to consent or approve (step-up).

Any OpenID Connect provider can answer both: Auth0, Keycloak, Microsoft Entra ID, Okta, PingFederate,
PingOne / Ping AIC, Curity, Cognito and others. `OidcSignIn` is a plain OIDC relying party (authorization
code + PKCE, nonce, ID token checked against the provider's JWKS). The PoC's demo password stays the
default so the demo runs with no IdP at all.

Configuration (environment):
  CUSTOMER_IDP=oidc            turn on OIDC sign-in (default: local demo password)
  OIDC_ISSUER                  the provider's issuer, exactly as it appears in its ID tokens
  OIDC_DISCOVERY_URL           optional: where the bank's server fetches metadata, if it differs from the
                               issuer (e.g. inside Docker: http://keycloak:8080/realms/marula/...)
  OIDC_CLIENT_ID, OIDC_CLIENT_SECRET   the bank's client registration (secret optional: public client + PKCE)
  OIDC_SCOPES                  default "openid profile email"
  OIDC_CUSTOMER_CLAIM          which ID-token claim identifies the customer (default preferred_username;
                               "email" suits Auth0 and Entra; a bank would usually use a customer-number claim)
"""
from __future__ import annotations

import hashlib
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt

from ..common.crypto import b64u

ID_TOKEN_ALGS = ["RS256", "PS256", "ES256"]


class SignInError(Exception):
    """Sign-in failed; the message is safe to show the customer."""


@dataclass
class OidcConfig:
    issuer: str
    client_id: str
    client_secret: str = ""
    discovery_url: str = ""
    scopes: str = "openid profile email"
    customer_claim: str = "preferred_username"
    redirect_uri: str = ""

    @classmethod
    def from_env(cls, bank_public_url: str) -> "OidcConfig | None":
        if os.environ.get("CUSTOMER_IDP", "local").lower() != "oidc":
            return None
        missing = [k for k in ("OIDC_ISSUER", "OIDC_CLIENT_ID") if not os.environ.get(k)]
        if missing:
            raise RuntimeError(f"CUSTOMER_IDP=oidc needs {', '.join(missing)}")
        return cls(issuer=os.environ["OIDC_ISSUER"].rstrip("/"), client_id=os.environ["OIDC_CLIENT_ID"],
                   client_secret=os.environ.get("OIDC_CLIENT_SECRET", ""),
                   discovery_url=os.environ.get("OIDC_DISCOVERY_URL", ""),
                   scopes=os.environ.get("OIDC_SCOPES", "openid profile email"),
                   customer_claim=os.environ.get("OIDC_CUSTOMER_CLAIM", "preferred_username"),
                   redirect_uri=bank_public_url.rstrip("/") + "/login/callback")


class OidcSignIn:
    """An OpenID Connect relying party for the bank's customer sign-in."""

    def __init__(self, cfg: OidcConfig, http: httpx.AsyncClient | None = None):
        self.cfg = cfg
        self.http = http or httpx.AsyncClient(timeout=10)
        self._meta: dict[str, Any] | None = None
        self._jwks: dict[str, Any] | None = None

    @property
    def name(self) -> str:
        return "oidc"

    async def metadata(self) -> dict[str, Any]:
        if self._meta is None:
            url = self.cfg.discovery_url or self.cfg.issuer + "/.well-known/openid-configuration"
            r = await self.http.get(url)
            r.raise_for_status()
            meta = r.json()
            if meta.get("issuer", "").rstrip("/") != self.cfg.issuer:
                raise RuntimeError(f"IdP metadata issuer {meta.get('issuer')!r} != OIDC_ISSUER {self.cfg.issuer!r}")
            self._meta = meta
        return self._meta

    async def _keys(self, refresh: bool = False) -> list[dict[str, Any]]:
        if self._jwks is None or refresh:
            r = await self.http.get((await self.metadata())["jwks_uri"])
            r.raise_for_status()
            self._jwks = r.json()
        return self._jwks.get("keys", [])

    # -------------------------------------------------------------- start
    async def start(self, step_up: bool) -> tuple[str, dict[str, Any]]:
        """Returns the IdP URL to send the browser to, and the state to keep in a signed cookie."""
        state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
        params = {"response_type": "code", "client_id": self.cfg.client_id, "redirect_uri": self.cfg.redirect_uri,
                  "scope": self.cfg.scopes, "state": state, "nonce": nonce,
                  "code_challenge": b64u(hashlib.sha256(verifier.encode()).digest()), "code_challenge_method": "S256"}
        if step_up:
            # Ask the IdP for a fresh sign-in. Which factor that means (passkey, biometrics, OTP) is the bank's policy,
            # set in its IdP; Valet only asks for "recently, by the customer".
            params |= {"max_age": "0", "prompt": "login"}
        url = (await self.metadata())["authorization_endpoint"] + "?" + urlencode(params)
        return url, {"state": state, "nonce": nonce, "verifier": verifier, "step_up": step_up, "started": int(time.time())}

    # ------------------------------------------------------------- finish
    async def finish(self, code: str, state: str, kept: dict[str, Any]) -> dict[str, Any]:
        """Swap the code, check the ID token, and return its claims."""
        if not code or not kept or not secrets.compare_digest(state or "", kept.get("state", "")):
            raise SignInError("This sign-in has expired or did not start here. Please try again.")
        meta = await self.metadata()
        form = {"grant_type": "authorization_code", "code": code, "redirect_uri": self.cfg.redirect_uri,
                "code_verifier": kept["verifier"], "client_id": self.cfg.client_id}
        auth = (self.cfg.client_id, self.cfg.client_secret) if self.cfg.client_secret else None
        r = await self.http.post(meta["token_endpoint"], data=form, auth=auth)
        if r.status_code != 200:
            raise SignInError("The sign-in service did not accept this sign-in. Please try again.")
        id_token = r.json().get("id_token")
        if not id_token:
            raise SignInError("The sign-in service returned no ID token.")
        return await self.check_id_token(id_token, kept)

    async def check_id_token(self, id_token: str, kept: dict[str, Any]) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as e:
            raise SignInError("The sign-in service returned an unreadable ID token.") from e
        if header.get("alg") not in ID_TOKEN_ALGS:
            raise SignInError("The ID token uses an algorithm the bank does not accept.")
        key = await self._key_for(header.get("kid"), header["alg"])
        try:
            claims = jwt.decode(id_token, key, algorithms=[header["alg"]], audience=self.cfg.client_id,
                                issuer=self.cfg.issuer, leeway=60, options={"require": ["exp", "iat", "sub", "nonce"]})
        except jwt.PyJWTError as e:
            raise SignInError(f"The ID token was rejected ({e}).") from e
        if not secrets.compare_digest(str(claims.get("nonce")), kept.get("nonce", "")):
            raise SignInError("The ID token does not belong to this sign-in.")
        if kept.get("step_up"):
            auth_time = claims.get("auth_time")
            if not isinstance(auth_time, (int, float)) or auth_time < kept["started"] - 5:
                raise SignInError("Please sign in again to confirm it's you.")
        return claims

    async def _key_for(self, kid: str | None, alg: str):
        for refresh in (False, True):                       # one refresh covers the IdP rotating its keys
            for k in await self._keys(refresh):
                if (kid is None or k.get("kid") == kid) and k.get("use", "sig") == "sig":
                    try:
                        return jwt.PyJWK(k, algorithm=alg).key
                    except jwt.PyJWTError:
                        continue
        raise SignInError("The ID token was signed with a key the sign-in service does not publish.")

    def customer_value(self, claims: dict[str, Any]) -> str:
        value = claims.get(self.cfg.customer_claim)
        if not value:
            raise SignInError(f"The sign-in service did not say who you are (no {self.cfg.customer_claim!r} claim).")
        return str(value)
