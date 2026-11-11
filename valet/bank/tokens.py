"""
Access tokens from more than one issuer.

Valet supports two ways of deploying with a bank's identity platform (design section 12):

  Federated  Valet's authorisation server issues the agent's tokens; the bank's IdP signs the customer in (idp.py).
             Works with any OpenID Connect provider.
  Native     The bank's own authorisation server (PingFederate, Auth0, Curity, Keycloak with extensions...) issues
             DPoP-bound tokens with authorization_details. Valet's enforcement verifies those tokens here, and the
             IdP registers each consent with Valet's grant service (POST /internal/grants) so that pause, revoke,
             limits and receipts work exactly as in federated mode.

Either way the banking API runs the same checks on every call. This module only answers: is this token genuine,
and what does it say?

External issuers are configured with VALET_EXTERNAL_ISSUERS, a JSON list:
  [{"issuer": "https://login.bank.example/", "jwks_uri": "https://login.bank.example/.well-known/jwks.json",
    "audience": "marula-api", "grant_claim": "valet_grant"}]
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt

ACCESS_TOKEN_ALGS = ["RS256", "PS256", "ES256"]


class TokenRejected(Exception):
    pass


@dataclass
class ExternalIssuer:
    issuer: str
    audience: str
    jwks_uri: str = ""
    jwks: dict[str, Any] | None = None                    # inline keys (tests), else fetched from jwks_uri
    grant_claim: str = "valet_grant"                      # where the IdP puts the Valet grant id
    client_claims: tuple[str, ...] = ("client_id", "azp")  # where the IdP puts the agent's client id
    http: httpx.Client | None = field(default=None, repr=False)

    def _keys(self, refresh: bool = False) -> list[dict[str, Any]]:
        if (self.jwks is None or refresh) and self.jwks_uri:
            r = (self.http or httpx.Client(timeout=10)).get(self.jwks_uri)
            r.raise_for_status()
            self.jwks = r.json()
        return (self.jwks or {}).get("keys", [])

    def _key(self, kid: str | None, alg: str):
        for refresh in (False, True):
            for k in self._keys(refresh):
                if kid is None or k.get("kid") == kid:
                    try:
                        return jwt.PyJWK(k, algorithm=alg).key
                    except jwt.PyJWTError:
                        continue
            if not self.jwks_uri:
                break
        raise TokenRejected("signing key not published by the issuer")

    def verify_client(self, token: str, audience: str) -> dict[str, Any]:
        """A client-credentials token (an application calling the consent service): no consent reference needed."""
        try:
            header = jwt.get_unverified_header(token)
            alg = header.get("alg")
            if alg not in ACCESS_TOKEN_ALGS:
                raise TokenRejected(f"algorithm {alg!r} not accepted")
            claims = jwt.decode(token, self._key(header.get("kid"), alg), algorithms=[alg], audience=audience,
                                issuer=self.issuer, leeway=30, options={"require": ["exp", "iat"]})
        except jwt.PyJWTError as e:
            raise TokenRejected(str(e)) from e
        client_id = next((claims[c] for c in self.client_claims if claims.get(c)), None)
        if not client_id:
            raise TokenRejected("token does not name the client (client_id)")
        return {**claims, "client_id": client_id}

    def verify(self, token: str) -> dict[str, Any]:
        """Verify and normalise to the claims Valet's enforcement reads."""
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as e:
            raise TokenRejected(f"unreadable token: {e}") from e
        alg = header.get("alg")
        if alg not in ACCESS_TOKEN_ALGS:
            raise TokenRejected(f"algorithm {alg!r} not accepted")
        try:
            claims = jwt.decode(token, self._key(header.get("kid"), alg), algorithms=[alg], audience=self.audience,
                                issuer=self.issuer, leeway=30, options={"require": ["exp", "iat"]})
        except jwt.PyJWTError as e:
            raise TokenRejected(str(e)) from e
        client_id = next((claims[c] for c in self.client_claims if claims.get(c)), None)
        if not client_id:
            raise TokenRejected("token does not name the agent (client_id)")
        if not claims.get(self.grant_claim):
            raise TokenRejected(f"token does not carry a Valet grant ({self.grant_claim!r} claim)")
        if not (claims.get("cnf") or {}).get("jkt"):
            raise TokenRejected("token is not DPoP-bound (no cnf.jkt)")
        details = claims.get("authorization_details") or []
        if isinstance(details, str):                       # some IdPs emit RAR as a JSON string claim
            details = json.loads(details)
        return {"iss": self.issuer, "client_id": client_id, "grant_id": claims[self.grant_claim],
                "authorization_details": details, "cnf": claims["cnf"], "jti": claims.get("jti"),
                "exp": claims["exp"], "external": True}


def external_issuers_from_env() -> dict[str, ExternalIssuer]:
    raw = os.environ.get("VALET_EXTERNAL_ISSUERS", "").strip()
    if not raw:
        return {}
    out = {}
    for item in json.loads(raw):
        iss = ExternalIssuer(issuer=item["issuer"], audience=item["audience"], jwks_uri=item.get("jwks_uri", ""),
                             grant_claim=item.get("grant_claim", "valet_grant"),
                             client_claims=tuple(item.get("client_claims", ("client_id", "azp"))))
        out[iss.issuer] = iss
    return out
