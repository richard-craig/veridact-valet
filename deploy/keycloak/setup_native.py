#!/usr/bin/env python3
"""
Configure the Keycloak realm for native mode: Keycloak issues Kaya's tokens, Valet keeps the rules.

Needs the Valet extension installed (extensions/keycloak-valet) and Kaya's public key, which Kaya publishes to
$VALET_DATA/agents/kaya.json on start-up (in a real deployment: the agent operator's registered JWKS).

    KEYCLOAK_URL=http://localhost:8080 VALET_DATA=./data python deploy/keycloak/setup_native.py

Creates (idempotently):
  - flow "valet browser": [sign in (cookie | username+password)] then [Valet AI-agent consent]
  - client "kaya": confidential, private_key_jwt (ES256), DPoP-bound tokens, PAR and PKCE required,
    marked valet.agent=true, using the flow above, with the valet_grant and marula-api audience mappers
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from urllib.parse import quote

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))   # the repo root, for valet.common

KC = os.environ.get("KEYCLOAK_URL", "http://localhost:8080").rstrip("/")
REALM = os.environ.get("KEYCLOAK_REALM", "marula")
DATA = Path(os.environ.get("VALET_DATA", "./data"))
KAYA_REDIRECT = os.environ.get("KAYA_PUBLIC_URL", "http://localhost:8001").rstrip("/") + "/callback"
from valet.common.crypto import jwk_thumbprint  # noqa: E402  (same kid the SDK puts in its assertions)

FLOW, SUBFLOW = "valet browser", "valet sign-in"


def admin() -> httpx.Client:
    r = httpx.post(f"{KC}/realms/master/protocol/openid-connect/token",
                   data={"grant_type": "password", "client_id": "admin-cli",
                         "username": os.environ.get("KC_ADMIN", "admin"), "password": os.environ.get("KC_ADMIN_PASSWORD", "admin")})
    r.raise_for_status()
    return httpx.Client(base_url=f"{KC}/admin/realms/{REALM}", headers={"Authorization": "Bearer " + r.json()["access_token"]},
                        timeout=20)


def ok(r: httpx.Response) -> httpx.Response:
    if r.status_code >= 400:
        sys.exit(f"{r.request.method} {r.request.url} -> {r.status_code} {r.text}")
    return r


def main() -> None:
    kaya = json.loads((DATA / "agents" / "kaya.json").read_text())
    jwk = {k: kaya["jwk"][k] for k in ("kty", "crv", "x", "y")}
    jwk |= {"use": "sig", "alg": "ES256", "kid": jwk_thumbprint(jwk)}

    c = admin()
    # ---- clean slate for re-runs
    for client_id in ("kaya", "acme-budgeting", "claude"):     # every client bound to the flow, before the flow itself
        for cl in ok(c.get("/clients", params={"clientId": client_id})).json():
            ok(c.delete(f"/clients/{cl['id']}"))
    for f in ok(c.get("/authentication/flows")).json():
        if f["alias"] == FLOW:
            ok(c.delete(f"/authentication/flows/{f['id']}"))

    # ---- the flow
    ok(c.post("/authentication/flows", json={"alias": FLOW, "providerId": "basic-flow", "topLevel": True, "builtIn": False,
                                              "description": "Sign in, then Valet consent for AI agents"}))
    ok(c.post(f"/authentication/flows/{quote(FLOW)}/executions/flow",
              json={"alias": SUBFLOW, "type": "basic-flow", "provider": "registration-page-form", "description": "Sign in"}))
    for provider in ("auth-cookie", "auth-username-password-form"):
        ok(c.post(f"/authentication/flows/{quote(SUBFLOW)}/executions/execution", json={"provider": provider}))
    ok(c.post(f"/authentication/flows/{quote(FLOW)}/executions/execution", json={"provider": "valet-consent"}))
    want = {SUBFLOW: "REQUIRED", "auth-cookie": "ALTERNATIVE", "auth-username-password-form": "ALTERNATIVE",
            "valet-consent": "REQUIRED"}
    for ex in ok(c.get(f"/authentication/flows/{quote(FLOW)}/executions")).json():
        key = ex.get("providerId") or ex.get("displayName")
        if key in want:
            ok(c.put(f"/authentication/flows/{quote(FLOW)}/executions", json={**ex, "requirement": want[key]}))
    flow_id = next(f["id"] for f in ok(c.get("/authentication/flows")).json() if f["alias"] == FLOW)

    # ---- the agent client
    ok(c.post("/clients", json={
        "clientId": "kaya", "name": "Kaya (fictional AI agent)", "protocol": "openid-connect", "enabled": True,
        "publicClient": False, "clientAuthenticatorType": "client-jwt", "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False, "implicitFlowEnabled": False, "redirectUris": [KAYA_REDIRECT],
        "authenticationFlowBindingOverrides": {"browser": flow_id},
        "attributes": {"valet.agent": "true", "use.jwks.string": "true", "jwks.string": json.dumps({"keys": [jwk]}),
                       "token.endpoint.auth.signing.alg": "ES256", "dpop.bound.access.tokens": "true",
                       "pkce.code.challenge.method": "S256", "require.pushed.authorization.requests": "true",
                       "access.token.lifespan": os.environ.get("KAYA_TOKEN_LIFESPAN", "300")},
        "protocolMappers": [
            {"name": "valet grant", "protocol": "openid-connect", "protocolMapper": "valet-grant-mapper",
             "config": {"access.token.claim": "true", "introspection.token.claim": "true", "id.token.claim": "false",
                        "userinfo.token.claim": "false"}},
            {"name": "marula-api audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
             "config": {"included.custom.audience": "marula-api", "access.token.claim": "true",
                        "id.token.claim": "false", "introspection.token.claim": "true"}}]}))
    setup_consent_app(c, flow_id)
    setup_mcp_client(c, flow_id)
    print(f"realm {REALM}: flow '{FLOW}' and client 'kaya' (kid {jwk['kid'][:12]}…) configured")
    for ex in ok(c.get(f"/authentication/flows/{quote(FLOW)}/executions")).json():
        print(f"  {'  ' * ex['level']}{ex['displayName']}: {ex['requirement']}")


CONSENT_SCOPES = ("consents:write", "consents:read")
ACME_REDIRECT = os.environ.get("ACME_PUBLIC_URL", "http://localhost:8002").rstrip("/") + "/callback"


def setup_consent_app(c: httpx.Client, flow_id: str) -> None:
    """Acme Budgeting: an app using the Consent Service. Client-credentials tokens (scopes consents:write/read,
    audience valet-consent) to create consents; authorization code + PAR with consent_id for the customer's approval;
    DPoP-bound tokens carrying the consent id as valet_grant."""
    path = DATA / "apps" / "acme.json"
    if not path.exists():
        print("  (Acme Budgeting has not published its key yet: skipped; re-run after it starts)")
        return
    acme = json.loads(path.read_text())
    jwk = {k: acme["jwk"][k] for k in ("kty", "crv", "x", "y")}
    jwk |= {"use": "sig", "alg": "ES256", "kid": jwk_thumbprint(jwk)}
    existing = {s_["name"]: s_["id"] for s_ in ok(c.get("/client-scopes")).json()}
    for name in CONSENT_SCOPES:
        if name not in existing:
            ok(c.post("/client-scopes", json={"name": name, "protocol": "openid-connect",
                                               "attributes": {"include.in.token.scope": "true",
                                                              "display.on.consent.screen": "false"}}))
    existing = {s_["name"]: s_["id"] for s_ in ok(c.get("/client-scopes")).json()}
    for cl in ok(c.get("/clients", params={"clientId": acme["client_id"]})).json():
        ok(c.delete(f"/clients/{cl['id']}"))
    ok(c.post("/clients", json={
        "clientId": acme["client_id"], "name": "Acme Budgeting (fictional third-party app)", "protocol": "openid-connect",
        "enabled": True, "publicClient": False, "clientAuthenticatorType": "client-jwt", "standardFlowEnabled": True,
        "serviceAccountsEnabled": True, "directAccessGrantsEnabled": False, "implicitFlowEnabled": False,
        "redirectUris": [ACME_REDIRECT], "authenticationFlowBindingOverrides": {"browser": flow_id},
        "attributes": {"valet.consent": "true", "use.jwks.string": "true", "jwks.string": json.dumps({"keys": [jwk]}),
                       "token.endpoint.auth.signing.alg": "ES256", "dpop.bound.access.tokens": "true",
                       "pkce.code.challenge.method": "S256", "require.pushed.authorization.requests": "true",
                       "access.token.lifespan": os.environ.get("ACME_TOKEN_LIFESPAN", "600")},
        "protocolMappers": [
            {"name": "consent reference", "protocol": "openid-connect", "protocolMapper": "valet-grant-mapper",
             "config": {"access.token.claim": "true", "introspection.token.claim": "true", "id.token.claim": "false",
                        "userinfo.token.claim": "false"}},
            *[{"name": f"{aud} audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
               "config": {"included.custom.audience": aud, "access.token.claim": "true", "id.token.claim": "false",
                          "introspection.token.claim": "true"}} for aud in ("marula-api", "valet-consent")]]}))
    cid = ok(c.get("/clients", params={"clientId": acme["client_id"]})).json()[0]["id"]
    for name in CONSENT_SCOPES:
        ok(c.put(f"/clients/{cid}/default-client-scopes/{existing[name]}"))
    print(f"  client '{acme['client_id']}': client credentials + PAR with consent_id, DPoP, scopes {', '.join(CONSENT_SCOPES)}")


MCP_RESOURCE = os.environ.get("VALET_MCP_RESOURCE", "http://localhost:8000/mcp")
CLAUDE_SECRET = os.environ.get("CLAUDE_CLIENT_SECRET", "claude-demo-secret-change-me")
CLAUDE_REDIRECTS = ["https://claude.ai/api/mcp/auth_callback", "https://claude.com/api/mcp/auth_callback",
                    "http://localhost/*", "http://127.0.0.1/*",
                    *filter(None, os.environ.get("CLAUDE_EXTRA_REDIRECTS", "").split(","))]


def setup_mcp_client(c: httpx.Client, flow_id: str) -> None:
    """Claude, connecting through the bank's MCP gateway: a pre-registered confidential client (client secret),
    authorization code + PKCE, bearer tokens (Claude sends no DPoP yet) audience-bound to the gateway, 5 minutes."""
    ok(c.post("/clients", json={
        "clientId": "claude", "name": "Claude (AI assistant, via the MCP gateway)", "protocol": "openid-connect",
        "enabled": True, "publicClient": False, "clientAuthenticatorType": "client-secret", "secret": CLAUDE_SECRET,
        "standardFlowEnabled": True, "directAccessGrantsEnabled": False, "implicitFlowEnabled": False,
        "serviceAccountsEnabled": False, "redirectUris": CLAUDE_REDIRECTS,
        "authenticationFlowBindingOverrides": {"browser": flow_id},
        "attributes": {"valet.agent": "true", "pkce.code.challenge.method": "S256",
                       "access.token.lifespan": os.environ.get("CLAUDE_TOKEN_LIFESPAN", "300"),
                       "use.refresh.tokens": "true", "client.use.lightweight.access.token.enabled": "false"},
        "protocolMappers": [
            {"name": "valet mandate", "protocol": "openid-connect", "protocolMapper": "valet-grant-mapper",
             "config": {"access.token.claim": "true", "introspection.token.claim": "true", "id.token.claim": "false",
                        "userinfo.token.claim": "false"}},
            {"name": "gateway audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
             "config": {"included.custom.audience": MCP_RESOURCE, "access.token.claim": "true",
                        "id.token.claim": "false", "introspection.token.claim": "true"}}]}))
    print(f"  client 'claude': confidential, PKCE, bearer tokens for {MCP_RESOURCE}")


if __name__ == "__main__":
    main()
