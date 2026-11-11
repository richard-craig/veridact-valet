# Veridact Valet

**Let people use AI agents with their money without handing over the keys to it.**

People are already giving AI assistants their banking passwords. Valet replaces that with a permission the customer
grants in their own bank's app: scoped to what the agent may do, limited in rands, bound to the agent's key,
stoppable in one tap, and recorded in a signed receipt for every decision.

Think of a valet key: it starts the car but won't open the boot. Valet gives an AI agent the same kind of key to a bank account.

This repository holds the design and a working proof of concept. The design is in [`docs/`](docs/):

- [Technical design](docs/technical-design.md): the profile, data model, flows, check order, receipts, security and identity-provider support.
- [MCP gateway design](docs/mcp-gateway-design.md) (draft, not yet built): how Claude, ChatGPT, Copilot and Gemini connect through a bank-run MCP gateway.

The proof of concept contains:

| Part | What it is |
|---|---|
| **Marula Bank** (`valet/bank`) | A fictional bank: a minimal OAuth 2.0 / FAPI 2.0-style authorisation server, a banking API with Valet's checks, Valet's grant service, and the customer's "AI agents" screens. |
| **Kaya** (`valet/agent`) | A fictional money-assistant agent and the small client SDK it uses. Kaya never sees a password, PIN or OTP. |
| `demo.py` | A scripted end-to-end run: 13 steps, 22 checks, exits non-zero if any protection fails. |
| `tests/` | 49 behaviour tests, including the bank's own identity provider in both deployment modes. |
| `extensions/keycloak-valet` | A Keycloak extension (Java) for native mode: hands the customer to Valet's consent screen mid-login and puts the Valet grant id in Keycloak's tokens. |

> Marula Bank, Kaya, Kaya Labs and Thandi are fictional, as are all account numbers. This is a demonstration,
> not production software (see [What this is not](#what-this-is-not)).

## What Valet is, and who runs it

Valet is an **open-source project**: a profile of open standards, reference code, an agent SDK and a test suite.
It is not a hosted service. **A bank that adopts Valet deploys it in its own environment, runs it, and keeps
control of every decision.** Nothing in Valet calls home, and no customer data leaves the bank.

| Valet provides (the project) | The bank keeps (its own deployment) |
|---|---|
| **The profile**: what "View only" and "Bill payer" mean as `authorization_details`, the approval rules, the check order on every call, error codes and the receipt format | **Customer identity and sign-in**: its existing IdP, app, passkeys or biometrics, and step-up policy |
| **Reference components**: grant service, enforcement for the banking API, approval flow, receipt chain, and an authorisation server for IdPs that lack the features | **Policy**: which access levels to offer, limit ceilings, grant lengths, which accounts, approval thresholds |
| **Adapters and guides** for identity providers (OIDC sign-in for any provider; native mode for providers with PAR, RAR and DPoP) | **Which agents to admit**, and when to withdraw trust (the Veridact registry can inform this; the bank decides) |
| **Screen designs** for consent, approvals and the AI agents list, as templates | **Its brand, its app and its push notifications** |
| **An agent SDK**, so agent builders integrate once for every bank | **Keys, data and records**: HSM keys, the database, receipt retention, POPIA obligations |
| **Conformance tests**: the scripted demo and test suite, extended into a suite a bank or agent can run | **Payments, fraud monitoring, disputes and customer support** |
| | **Operations**: hosting, patching, monitoring, scaling, and the conversation with regulators |

Veridact (the company) can separately offer support, integration help, certification and the agent registry.
None of that is needed to run the code.

### "We'll just implement the open standards"

Good, so does Valet. It uses OAuth 2.0, FAPI 2.0, PAR, RAR, DPoP, CIBA and `private_key_jwt`, and nothing else.
But the standards are the envelope, not the letter inside it. RAR, for example, carries `authorization_details`
whose types and meaning **each implementer defines**. If every bank defines "pay my bills" differently, every
agent builder has to integrate with every bank separately. Most won't, and customers keep handing over passwords.

What Valet adds on top of the standards, so each bank doesn't have to design, build and test it alone:

- **A shared vocabulary**: the same permission types, levels and error codes at every bank, so one agent
  integration works everywhere.
- **The decisions no RFC makes**: checking grant status on every call, a monthly ledger in rands, approvals only
  for actions the bank itself offered, single-use approvals that never add a beneficiary, what to do when a refresh
  token is reused, and what the consent and approval screens must show.
- **Working, tested code** for each of those, and tests that prove a deployment behaves.
- **No lock-in**: Apache 2.0 licensed, built only on open standards, and it runs on the identity platform the bank
  already has.

## Consent Service: one consent model for every application

Valet's AI-agent grants are one case of a wider need: a **standard consent model any application can use**. The
Consent Service ([`docs/consent-service-openapi.yaml`](docs/consent-service-openapi.yaml), live at
`/consent/v1/docs`) follows the UK Open Banking intent-based pattern, generalised with RFC 9396 `authorization_details`:

1. The app gets a client-credentials token from the bank's IdP (`private_key_jwt`, DPoP, scope `consents:write`)
   and **creates the consent first**: `POST /consent/v1/consents` → `AwaitingAuthorisation`, no customer yet.
2. It sends the customer to the bank's IdP with the `consent_id` (PAR). The IdP signs them in and hands them to
   the bank's approval screen, which shows the consent in plain language; the customer picks accounts.
3. The IdP's token carries **only a reference** (`valet_grant` = the consent id). The bank's APIs (`/ob/v1/...`)
   ask for a decision on every call: `permit`, `deny` or `step_up_required`, with reserve-and-settle for amounts
   and a signed receipt for each decision.
4. Revoking (customer in the bank app under *Connected apps*, or the app itself) stops a still-valid token on its
   next call, and the app receives a signed Security Event Token (RFC 8417) at its webhook.

Types: `account_information`, `payment_initiation`, `recurring_payment`, `customer_profile` and
`delegated_action` (with an `actor`, for AI agents and advisers). The demo app **Acme Budgeting**
(`valet/apps/acme.py`, port 8002) runs this end to end through Keycloak in the native stack; `tests/test_consents.py`
covers the rules. In the PoC the Consent Service and Valet's agent grants are separate stores; a bank deployment
converges them on the consent store.

## Identity providers

Valet does not replace the bank's identity platform. It works with it in one of two modes, and the banking API's
checks are identical in both.

**Federated mode (any OpenID Connect provider).** Valet's authorisation server handles the agent side (PAR, RAR,
DPoP, CIBA). The bank's IdP signs the customer in and runs step-up. This works with Auth0, Keycloak, Microsoft Entra
ID, Okta, PingFederate, PingOne, Curity, Amazon Cognito or any other OIDC provider, because all Valet asks of the IdP
is plain OpenID Connect.

```bash
CUSTOMER_IDP=oidc
OIDC_ISSUER=https://your-tenant.eu.auth0.com/          # exactly as in the ID token's iss
OIDC_CLIENT_ID=...  OIDC_CLIENT_SECRET=...
OIDC_CUSTOMER_CLAIM=email                              # or preferred_username, or a customer-number claim
# optional: OIDC_DISCOVERY_URL when the server reaches the IdP at a different address (Docker)
```

Register `http://localhost:8000/login/callback` (or your bank URL plus `/login/callback`) as the redirect URI.
Consent and approvals ask the IdP for a fresh sign-in (`max_age=0`, `prompt=login`) when the session is older than
`STEP_UP_MAX_AGE` seconds (default 300). The IdP decides what a fresh sign-in means.

**Native mode (the bank's own authorisation server issues agent tokens).** For a platform that already supports
PAR, RAR and DPoP (PingFederate, Auth0 with Highly Regulated Identity, Curity, and Keycloak with a RAR extension),
the bank can keep its authorisation server. The IdP registers each consent with Valet's grant service
(`POST /internal/grants`) and puts the returned grant id in its tokens. Valet's enforcement verifies those tokens
with the IdP's published keys, so pause, revoke, limits, approvals and receipts still work:

```bash
VALET_EXTERNAL_ISSUERS='[{"issuer": "https://login.bank.example/", "jwks_uri": "https://login.bank.example/.well-known/jwks.json",
                          "audience": "marula-api", "grant_claim": "valet_grant"}]'
VALET_INTERNAL_SECRET=...      # PoC only: production uses mTLS between the IdP and Valet
```

**Native mode on Keycloak in one command** (Docker; the first run builds Keycloak 26.4 with the extension baked in):

```bash
docker compose -f docker-compose.native.yml up --build    # wait for "valet-setup exited with code 0"
python scripts/preflight.py                               # 13 checks through real Keycloak: READY or NOT READY
docker compose -f docker-compose.native.yml down -v       # reset to a clean slate
```

Kaya on http://localhost:8001, Marula Bank on http://localhost:8000, Keycloak on http://localhost:8080
(admin / admin); Thandi signs in as `thandi` / `demo` on Keycloak's page. For a hosted demo over HTTPS on a VM, add
`docker-compose.vm.yml` (see the comments in it). It has to be HTTPS: Keycloak 26 marks its login cookies `Secure`,
and browsers only send those over plain http to `localhost`.

**Native mode on Keycloak** uses the extension in [`extensions/keycloak-valet`](extensions/keycloak-valet/README.md).
Keycloak signs the customer in, then hands them to Valet's consent screen. It issues Kaya's DPoP-bound tokens
carrying the Valet grant id, while Valet's checks, approvals, pause and receipts work unchanged. To run it locally
against a Keycloak 26.4 install (`KEYCLOAK_HOME`):

```bash
(cd extensions/keycloak-valet && ./build.sh) && cp extensions/keycloak-valet/target/*.jar $KEYCLOAK_HOME/providers/
# Keycloak, with the realm in deploy/keycloak/ imported, and the hand-off settings:
VALET_CONSENT_URL=http://localhost:8000/handoff/consent VALET_ISSUER=http://localhost:8000 \
VALET_HANDOFF_SECRET=<32+ chars> $KEYCLOAK_HOME/bin/kc.sh start-dev --import-realm
# Bank: CUSTOMER_IDP=oidc + OIDC_* (as above), VALET_EXTERNAL_ISSUERS (Keycloak issuer, its JWKS URI, audience marula-api),
#       VALET_HANDOFF_SECRET (same value), VALET_HANDOFF_IDPS='{"keycloak:marula": "http://localhost:8080/realms/marula/"}'
# Kaya: KAYA_CONNECT_VIA=http://localhost:8080/realms/marula/.well-known/openid-configuration
python deploy/keycloak/setup_native.py      # once Kaya has started and published its key: flow, client, mappers
```

**What has been run.** Native mode was run end to end against **Keycloak 26.4.0** with the extension. Kaya connected
through Keycloak, paid within its limit, and got an approval for a new recipient. Its Keycloak token refreshed, and a
pause in the bank app stopped it at once. Declines and forged hand-off results were refused. Federated mode was run
end to end in a browser against **Keycloak 26.4.0** using the realm in `deploy/keycloak/`. That covered sign-in on Keycloak's page, consent, payment, and an approval that forced a fresh
Keycloak sign-in (the bank checked Keycloak's `auth_time`). The test suite covers both modes against a mock provider
that signs with RSA, as Auth0, Keycloak, Entra ID and Okta do by default. Not yet run: a real Auth0, Entra ID, Okta
or Ping tenant, and the native-mode hooks for Auth0 (an Action) and PingFederate (a token mapping).

The design document has a support matrix for each platform. Feature support changes between versions, so confirm
it on the version the bank runs.

## Run it

Python 3.11 or later.

```bash
pip install -r requirements.txt

python demo.py          # scripted end-to-end demo, takes a second or two
python -m pytest -q     # behaviour tests
python run.py           # clickable demo: Kaya on :8001, Marula Bank on :8000
```

Or with Docker:

```bash
docker compose up --build             # clickable demo
docker compose run --rm demo          # scripted demo
docker compose run --rm demo pytest -q

# customers sign in with Keycloak instead of the demo password (thandi / demo on Keycloak's page)
docker compose -f docker-compose.yml -f docker-compose.keycloak.yml up --build
```

## Click through it

1. Open **Kaya** at <http://localhost:8001> and tap **Connect Marula Bank**.
2. You land on **Marula Bank's own** sign-in page, not Kaya's. Sign in as `thandi` with password `demo`.
3. The consent screen shows who Kaya is (verified operator, from the agent registry). Choose **Bill payer**, keep
   R2,000 a month, and confirm.
4. Back in Kaya:
   - **Pay the water bill** goes straight through (an existing beneficiary, inside the limit).
   - **Pay City Power** is held: a new recipient. Open <http://localhost:8000/app/approvals>, read the approval,
     which the bank builds (amount, recipient, scam warning; the agent's note is labelled as written by the agent),
     and approve. Kaya picks it up within a few seconds and pays once.
   - **Pay school fees** is over the monthly limit, so it is held for approval too. Try declining it.
   - **Add QuickLoans as a beneficiary** is refused. Agents can never add beneficiaries.
5. In Marula Bank, go to **AI agents › Kaya** to see every action with its receipt hash. Tap **Pause Kaya**, then try
   anything in Kaya: it is refused on the very next call. Resume, then **Disconnect** to end it for good.
6. <http://localhost:8000/ops> plays the bank (or Veridact): withdraw trust in Kaya's operator and every grant for
   Kaya stops at once. The page also verifies the receipt chain.

To start again, stop the servers and delete the `data/` folder (or `docker compose down -v`).

## What it proves

| Promise | How it is enforced | Where it is checked |
|---|---|---|
| The customer never shares credentials with the agent | Authorisation code flow; sign-in and consent happen only on the bank's pages | demo step 2 |
| Only verified agents can ask | `private_key_jwt` client authentication against the agent registry, before anything is shown to the customer | demo 1, test |
| The customer, not the agent, decides the scope | The bank builds the grant from the customer's choices on the consent screen, whatever the agent asked for | test |
| Requests cannot be swapped in the browser | PAR (RFC 9126) plus PKCE S256; `/authorize` refuses anything not pushed first | tests |
| A stolen token is useless | DPoP (RFC 9449): the token is bound to Kaya's key (`cnf.jkt`); each proof is single-use and bound to the method, URL and token | demo 3, test |
| Spending stays inside a monthly limit in rands, only to existing beneficiaries | Rich Authorization Requests (RFC 9396) types `valet_accounts` / `valet_payments`; a monthly ledger in SAST | demo 4, 7, test |
| Anything else needs the customer's approval, in the bank's app | The API returns `approval_required` with the exact action; the agent asks through CIBA (poll mode); the bank only accepts actions it offered | demo 5, test |
| An approval covers one payment, exactly as shown | Single-use, 5-minute, digest-bound `valet_payment_once` token; it neither adds a beneficiary nor uses the limit | demo 6, test |
| Agents can never add beneficiaries | Hard refusal in the API, recorded | demo 8, test |
| Pause, resume and disconnect are immediate | Grant status is checked on every API call, not only at token issue; pausing cancels pending approvals | demo 9, 12, test |
| A copied refresh token is caught | Rotation with reuse detection; reuse pauses the grant | demo 10, test |
| The bank or Veridact can stop an operator everywhere at once | Registry trust is checked on every call | demo 11, test |
| Every decision can be proven later | Hash-chained, ES256-signed receipts at the bank; tampering is detected | demo 13, test |
| The bank's IdP can issue the agent's tokens while Valet keeps the rules; forged consent results are refused | Keycloak extension: signed ticket and result with nonce; grant id in tokens; grant bound to the agent's DPoP key | `test_handoff.py`, Keycloak native run |
| The bank's own IdP signs customers in, and consent and approvals need a fresh sign-in | OIDC relying party (code + PKCE, nonce, JWKS-checked ID token); `max_age=0` step-up with `auth_time` checked | `test_idps.py`, Keycloak run |
| Tokens from the bank's own authorisation server get exactly the same checks | Verified with the issuer's keys; consent is the grant registered with Valet, so tokens cannot widen it | `test_idps.py` |

## How it fits together

```
 Customer's browser                Kaya (agent server)                    Marula Bank
 ──────────────────                ───────────────────                    ───────────
  tap "Connect"   ───────────────▶  POST /par  (private_key_jwt, PKCE, RAR) ─▶ checks registry
                  ◀── redirect to bank /authorize?request_uri=…
  sign in, choose level, confirm ─────────────────────────────────────────▶ grant + one-time code
                  ◀── redirect to Kaya /callback?code=…
                                    POST /token (code, verifier, DPoP)  ─▶ DPoP-bound token + refresh
                                    GET/POST /api/…  (DPoP each call)   ─▶ live checks, receipt
                                    403 approval_required (exact action) ◀─
                                    POST /bc-authorize (that action)    ─▶ approval in the bank app
  approve in the bank app ────────────────────────────────────────────────▶
                                    POST /token (CIBA poll)             ─▶ single-use token
                                    POST /api/payments (once)           ─▶ paid, receipt
```

### Layout

```
deploy/keycloak/   realm for the Keycloak option (fictional customer thandi / demo) and setup_native.py
extensions/keycloak-valet/   Keycloak extension for native mode (Java, Apache 2.0)
valet/
  common/   crypto.py (ES256, JWK thumbprints), dpop.py (proofs), money.py (integer cents, ZAR)
  bank/     authz.py (metadata, /par, /authorize, /token, /bc-authorize)
            api.py   (/api/accounts, /transactions, /payments, /beneficiaries)
            web.py   (sign-in, AI agents, approvals, ops)
            registry.py (AgentRegistry: StaticRegistry now, Veridact later)
            idp.py   (customer sign-in through any OpenID Connect provider)
            tokens.py, grants.py, handoff.py (native mode: the bank IdP's tokens, consent registration and hand-off)
            levels.py, receipts.py, store.py (SQLite), config.py, context.py, main.py, templates/
  agent/    sdk.py (ValetClient), kaya.py (demo agent web app), templates/
  testing/mock_idp.py  a tiny OIDC provider for tests (not for real use)
  harness.py  in-process bank + agent for demo.py and the tests
```

### The agent registry

`registry.py` defines an `AgentRegistry` interface: look up an agent by `client_id` (name, operator, keys,
redirect URIs) and ask whether it is trusted. The PoC ships `StaticRegistry`, which reads `data/trust.json` and
`data/agents/*.json`. Kaya publishes its own public key there on start-up, standing in for registration. A
`VeridactRegistry` that resolves agents through Veridact's verified directory is the intended production
implementation; nothing else in the bank needs to change.

## Configuration

| Variable | Used by | Default | Meaning |
|---|---|---|---|
| `BANK_PUBLIC_URL` | bank, Kaya | `http://localhost:8000` | The issuer, and where the customer's browser reaches the bank |
| `BANK_INTERNAL_URL` | Kaya | `http://localhost:8000` | Where Kaya's server reaches the bank (`http://bank:8000` in Compose) |
| `KAYA_PUBLIC_URL` | Kaya | `http://localhost:8001` | Used for Kaya's redirect URI |
| `VALET_DATA` | both | `./data` | SQLite database, demo keys, registry files |
| `BANK_SESSION_SECRET` | bank | demo value | Signs the customer's session cookie. Change it outside a laptop. |
| `CUSTOMER_IDP`, `OIDC_*` | bank | local | Customer sign-in through the bank's OpenID Connect provider (see [Identity providers](#identity-providers)) |
| `STEP_UP_MAX_AGE` | bank | `300` | Seconds a sign-in stays fresh enough to consent or approve |
| `VALET_EXTERNAL_ISSUERS`, `VALET_INTERNAL_SECRET` | bank | unset | Native mode: accept the bank IdP's tokens; let it register consents |
| `VALET_HANDOFF_SECRET`, `VALET_HANDOFF_IDPS` | bank | unset | Native mode: consent hand-off from the bank's IdP, and where results may be returned |
| `KAYA_CONNECT_VIA` | Kaya | unset | Native mode: the IdP's metadata URL; Kaya connects through it |

Limits live in `valet/bank/config.py`: token lifetimes (access 5 minutes, approval 5 minutes), maximum grant 90 days,
maximum monthly limit R5,000, at most 3 approvals waiting at once.

## What this is not

This PoC shows the protocol and the customer experience. It leaves out what a bank deployment needs:

- **Real authentication.** By default sign-in is a demo password and "Confirm with fingerprint" is a button. With
  `CUSTOMER_IDP=oidc` the bank's IdP signs customers in and handles step-up; a bank would use its app's passkeys or
  biometrics there.
- **Push notifications.** Approvals appear in the bank's web page; a bank sends them to its app.
- **Key custody.** Demo keys are PEM files on disk. Production keys belong in an HSM or KMS (the bank) and a KMS
  or secure enclave (the agent operator).
- **Scale and durability.** SQLite and one process. Grant status, replay caches and ledgers need shared,
  highly available storage.
- **The real registry.** `StaticRegistry` stands in for Veridact.
- **IdP hooks for native mode beyond Keycloak.** Keycloak's is built and run; Auth0's and PingFederate's are not.
  The Keycloak extension's own limits are in its README.
- **Transport.** No TLS here; FAPI 2.0 requires it, and the bank would usually add mTLS or a gateway.
- **Full FAPI 2.0 conformance.** The PoC follows the FAPI 2.0 pattern (PAR, PKCE, DPoP, private_key_jwt) but has
  not been through the OpenID conformance suite.

A bank does not have to adopt this code as it stands. It can run the reference components, or implement the
Valet profile on its own platform and prove it with the tests.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).

## Status

Version 0.1, a proof of concept. It is not production software and has not had an independent security review. See [SECURITY.md](SECURITY.md) to report a vulnerability and [CONTRIBUTING.md](CONTRIBUTING.md) to get involved.
