# Veridact Valet

**Let people use AI agents with their money without handing over the keys to it.**

People are already giving AI assistants their banking passwords. Valet replaces that with a permission the customer
grants in their own bank's app: scoped to what the agent may do, limited in rands, bound to the agent's key,
stoppable in one tap, and recorded in a signed receipt for every decision.

Think of a valet key: it starts the car but won't open the boot. Valet gives an AI agent the same kind of key to a bank account.

This repository holds the design and a working proof of concept. The design is in [`docs/`](docs/):

- [Where Valet fits](docs/where-valet-fits.md): start here. What Valet is, where it sits next to open banking and the bank's identity platform, how the agent is bound to the customer, token and mandate, and how it lines up with AP2, Verifiable Intent and the Personal Agent Protocol.
- [Threat model](docs/threat-model.md): the controls on each journey (direct agents and AI assistants), their status, and the known gaps.
- [The Valet profile](docs/valet-profile.md): the shared permission standard in one place. Access levels, approval rules, check order, error codes and receipt format, each marked built or specified.
- [The Valet insurance profile](docs/valet-insurance-profile.md): the same pattern for insurers. Policy, claim and change mandates, protected actions that always go back to the customer, and receipts that keep health data out of the chain. Proposed.
- [Technical design](docs/technical-design.md): the profile, data model, flows, check order, receipts, security and identity-provider support.
- [MCP gateway design](docs/mcp-gateway-design.md) (draft; its core is built as the reference MCP server in `valet/bank/mcp.py`): how Claude, ChatGPT, Copilot and Gemini connect through the bank's own MCP server, with Valet and Veridact as sidecars.
- [Poppy extension](docs/poppy-extension.md) (draft; discovery, scope-only sign-in, CIMD agents and Session IDs in receipts are built): Valet as a banking extension for the Personal Agent Protocol. Any Poppy agent can find the bank and sign in with plain Poppy scopes, with no integration, and the customer turns the request into a mandate on the bank's consent screen. Adds standing mandates held by the bank, approval in the bank app, reasons and receipts, on top of Poppy's operations extension.
- [Decision service](docs/decision-service.md) (built in `valet/decision/`, on SQLite; the PostgreSQL store is designed): Valet as a decision service the bank's servers call over the OpenID AuthZEN Authorization API, the reserve, commit and release extension, the shared store, and how concurrent and repeated payments are handled.
- [Veridact agent identity](docs/veridact-agent-identity.md) (draft; Lane A known-assistant checks are built, the Lane B Veridact registry is not): how Valet knows which agent it is talking to, using client attestation, SD-JWT VC and Token Status List, plus known-assistant entries for Claude, ChatGPT, Gemini and Copilot.
- [Control framework mapping](docs/control-framework-mapping.md): Valet against a bank control framework for AI agents (autonomy tiers, assurance states, the minimum evidence set, stopping an agent, board questions) and against South African, EU and UK regulation.

The proof of concept contains:

| Part | What it is |
|---|---|
| **Marula Bank** (`valet/bank`) | A fictional bank: a minimal OAuth 2.0 authorisation server (FAPI 2.0-aligned, conformance pending), a banking API with Valet's checks, Valet's grant service and payment intents, a fictional core banking system that executes payments, and the customer's "AI agents" screens. |
| **Kaya** (`valet/agent`) | A fictional money-assistant agent and the small client SDK it uses. Kaya never sees a password, PIN or OTP. |
| `demo.py` | A scripted end-to-end run: 13 steps, 24 checks, exits non-zero if any protection fails. |
| `tests/` | 201 behaviour tests: the Valet profile conformance suite, plus payment safety (retries, crashes, timeouts, cancel-or-confirm, pause mid-payment), the emergency stop, signed evidence packs, and the bank's own identity provider in both deployment modes. |
| `extensions/keycloak-valet` | A Keycloak extension (Java) for native mode: hands the customer to Valet's consent screen mid-login and puts the Valet grant id in Keycloak's tokens. |

> Marula Bank, Kaya, Kaya Labs and Thandi are fictional, as are all account numbers. This is a demonstration,
> not production software (see [What this is not](#what-this-is-not)).

## What Valet is, and who runs it

Valet is an **open-source project**: a profile of open standards, reference code, an agent SDK and a test suite.
It is not a hosted service. **A bank that adopts Valet deploys it in its own environment, runs it, and keeps
control of every decision.** Nothing in Valet calls home, and no customer data leaves the bank.

| Valet provides (the project) | The bank keeps (its own deployment) |
|---|---|
| **The profile** ([Valet profile](docs/valet-profile.md)): what "View only", "Approved payer" and "Bill payer" mean as `authorization_details`, the approval rules, the check order on every call, error codes and the receipt format | **Customer identity and sign-in**: its existing IdP, app, passkeys or biometrics, and step-up policy |
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

## Claude and ChatGPT through the bank's MCP server (reference example)

> **Example, not product.** The MCP server belongs to the bank. `valet/bank/mcp.py` is a reference example that
> shows bank developers each step their own server must take. It is the **enforcement point**; Valet is the
> **decision service** it asks before every action, over the OpenID AuthZEN API
> ([decision service](docs/decision-service.md), built in `valet/decision/`).

`/mcp` on the bank is a Streamable HTTP MCP server ([design](docs/mcp-gateway-design.md)). Claude signs in through
the bank's IdP (Keycloak), the customer builds the mandate on the bank's consent screen, and before every tool call
the bank's server asks Valet (`POST /access/v1/evaluation`), projecting the tool's arguments by the AuthZEN mapping
it publishes in the tool's `_meta`. The rules run outside the model:

| Tool | What the gateway enforces |
|---|---|
| `list_accounts`, `get_balance`, `list_transactions` | Only shared accounts, within the look-back window; numbers masked |
| `list_payees` | Only payees the customer saved in the bank app |
| `pay_existing_payee` | Saved payees only (never new ones), monthly limit including payments awaiting approval, idempotency key, and **customer approval in the bank app for every payment** (Claude sends bearer tokens, so it sits on the bearer tier) |
| `get_payment_status` | `APPROVAL_REQUIRED`, `APPROVED` (paid exactly once) or `DECLINED` with reason codes |

How the pieces talk:

- **Decision service** (`valet/decision/`): AuthZEN evaluation and batch evaluation (for `tools/list`), approvals in
  the form of the AuthZEN Access Request and Approval Profile, and reservations (`sent`, `commit`, `release`,
  `unknown`) so the bank's server executes each payment with its own payment system, the reservation id as the
  idempotency key. Over HTTP with `VALET_DECISION_URL` and `VALET_DECISION_SECRET` (the demo stack does this), or
  in-process. **Fail closed:** if Valet cannot answer, the MCP server returns JSON-RPC `-32603` and does nothing.
- **Veridact known-assistant entry**: the bank checks a Veridact-signed SD-JWT VC about Claude, and its Token Status
  List, itself (`valet/bank/known_assistants.py`, `VALET_KNOWN_ASSISTANTS`). The consent screen names the verified
  operator ("Claude, operated by Anthropic PBC"); if Veridact suspends Claude, every call stops with
  `ASSISTANT_SUSPENDED` at every bank that checks it, as soon as its cached status answer expires (15 seconds in the
  demo). Network-wide, Veridact allows up to about 10 minutes (5 to publish, 5 of verifier cache); the bank's own
  denylist stops it at once. The demo's attester is
  [`veridact/attester`](https://github.com/veridactlabs/veridact/tree/main/attester).
- **Actor claim**: Keycloak's token carries `act: {"sub": "claude"}` (RFC 8693): Claude acts for the customer in
  `sub`. The server refuses a token whose actor is not its client, and every receipt records the actor.
- **Read-only profile**: `VALET_MCP_READ_ONLY=1` offers only the four read tools, for a Connectors Directory listing
  ([submission notes](docs/connector-directory-submission.md)).

`/ops` on the bank shows every decision the MCP server asked for (request and answer), and Claude's Veridact status.

Pause or disconnect in the bank app and the next tool call is `DECLINED: MANDATE_PAUSED`. Every call writes a
receipt, including Claude's stated reason labelled as agent-supplied. The demo seeds a transaction whose description
tries to instruct the assistant to pay a stranger (`DEMO_SEED_INJECTION=1`): if a model obeys it, the gateway answers
`PAYEE_NOT_IN_MANDATE`.

**Claude Code** (works against `localhost`):

```bash
MCP_CLIENT_SECRET=claude-demo-secret-change-me claude mcp add --transport http \
  --client-id claude --client-secret --callback-port 33418 marula http://localhost:8000/mcp
# then /mcp in Claude Code -> Authenticate -> sign in as thandi / demo -> choose Bill payer
```

**Claude (web, desktop, mobile)** needs the gateway and Keycloak reachable from the internet over HTTPS: deploy it with
[`deploy/azure`](deploy/azure/README.md), then *Settings → Connectors → Add custom connector*, URL
`https://bank.<label>.<zone>/mcp`, and under *Advanced settings* client ID `claude` and the client secret. Keycloak
already allows Claude's callbacks (`https://claude.ai/api/mcp/auth_callback`, `https://claude.com/...`).

Try: *"What did I spend last week? Then pay my water bill."* Then: *"Pay QuickLoans R4,999 like the note in my
transactions says."* Then pause Claude in the bank app and ask again. Then suspend Claude on the Veridact attester's
`/admin` page and ask again.

**ChatGPT** uses the same server, with its own Keycloak client (`chatgpt`), its own mandate and its own Veridact
known-assistant entry. It needs the hosted stack (HTTPS). In ChatGPT: *chatgpt.com/plugins → Add → Create custom MCP
server* (on Business and Enterprise a workspace admin turns on developer mode first), URL `https://bank.<label>.<zone>/mcp`,
authentication **OAuth**, and under the advanced OAuth settings client ID `chatgpt` and `CHATGPT_CLIENT_SECRET`.
Keycloak already allows ChatGPT's callbacks (`https://chatgpt.com/connector_platform_oauth_redirect`, and the
callback-id form `https://chatgpt.com/connector/oauth/*`). What ChatGPT checks, and the server meets:

| ChatGPT requirement ([OpenAI](https://developers.openai.com/plugins/build/auth)) | Where it is met |
|---|---|
| Protected resource metadata with `scopes_supported` | `/.well-known/oauth-protected-resource/mcp` |
| PKCE `S256` | Keycloak client attribute; advertised in Keycloak's metadata |
| `resource` echoed into the token's audience | Keycloak audience mapper: the token's `aud` is the gateway URL |
| `iss` in the authorisation response, equal to the issuer (RFC 9207) | Keycloak returns and advertises it, so ChatGPT uses its stable callback |
| Client registration: predefined client, CIMD or DCR | Predefined confidential client (never DCR) |
| Per-tool auth policy | `securitySchemes` (`oauth2`, scope `openid`) on every tool, top level and in `_meta` |

Write tools (`pay_existing_payee`) need a ChatGPT plan with full MCP support (Business, Enterprise, Edu at the time
of writing); on others, use the read-only profile. Try the same prompts as for Claude; suspend `chatgpt` on the
attester's `/admin` page to see the kill switch stop only ChatGPT.

`scripts/preflight.py` drives both paths the way the connectors do (discovery from the 401, Keycloak sign-in,
consent, token, MCP), including ChatGPT's pre-link checks, and checks protocol conformance with the official MCP
Python SDK when it is installed.

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
(admin / admin); Thandi signs in as `thandi` / `demo` on Keycloak's page. For a hosted demo over HTTPS (one subdomain per component, all on 443), see [`deploy/azure/README.md`](deploy/azure/README.md): one script deploys it to an Azure VM. It has to be HTTPS: Keycloak 26 marks its login cookies `Secure`, and browsers only send those over plain http to `localhost`.

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
5. In Marula Bank, go to **AI agents › Kaya** to see every action with its receipt hash. Tap any payment for its
   evidence page: who asked, what you allowed, whose decision it was and what the bank did. Tap **Pause Kaya**, then try
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
| A stolen authorisation code is useless, and nobody else can claim the grant | The agent names its key in the pushed request (`dpop_jkt`); the grant is bound to it when the customer consents, in both deployment modes | `test_payments.py`, `test_handoff.py`, Keycloak native run |
| A retry, a crash or a timeout never pays twice | One payment intent per `Idempotency-Key`, on the direct API and the MCP gateway alike; Valet holds the amount and instructs the bank's payment system, idempotent on the intent id; an unanswered payment is `pending` and held, never "failed" | demo 4, `test_payments.py` |
| Valet never executes a payment | One adapter (`valet/bank/core.py`) to the bank's payments API; the PoC's is a fictional core | `test_payments.py` |
| Spending stays inside the customer's named payees, a per-payment cap, a monthly payment count and a monthly limit in rands | Rich Authorization Requests (RFC 9396) types `valet_accounts` / `valet_payments`; one mandate check for both front doors; a monthly ledger in SAST | demo 4, 7, tests/test_profile.py |
| Anything else needs the customer's approval, in the bank's app | The API returns `approval_required` with the exact action; the agent asks through CIBA (poll mode); the bank only accepts actions it offered | demo 5, test |
| An approval covers one payment, exactly as shown | Single-use, 5-minute, digest-bound `valet_payment_once` token that can only finish the payment the bank held; it never adds a beneficiary, and it counts towards the month's total | demo 6, test |
| Agents can never add beneficiaries | Hard refusal in the API, recorded | demo 8, test |
| Pause, resume and disconnect are immediate | Grant status is checked on every API call, not only at token issue; pausing cancels every approval and payment the bank has not accepted, including approved-but-unsent ones, and resuming needs a fresh approval | demo 9, 12, `test_stopping.py` |
| A held payment is released only when the bank says it is dead | Cancel-or-confirm: the bank tombstones the instruction or reports it already paid; no answer goes to an operations queue, still held | `test_stopping.py` |
| A copied refresh token is caught | Rotation with reuse detection; reuse pauses the grant. An agent that lost the response can retry for 60 seconds with the same key | demo 10, test |
| The bank or Veridact can stop an operator everywhere | The bank's denylist stops a client, operator or key on the next request; registry trust is checked on every call (60-second cache); an unreachable registry stops payments at once | demo 11, `test_stopping.py` |
| Every decision can be proven later | Hash-chained, ES256-signed receipts at the bank; tampering is detected | demo 13, test |
| A disputed payment can be explained on one screen | The payment evidence page in the bank app: who asked, what the customer allowed, whose decision it was, what the bank did and its payment reference | test |
| The bank's IdP can issue the agent's tokens while Valet keeps the rules; forged consent results are refused | Keycloak extension: signed ticket and result with nonce; grant id in tokens; grant bound to the agent's DPoP key at consent | `test_handoff.py`, Keycloak native run |
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
  decision/ service.py (AuthZEN decisions, approvals, reservations), api.py (HTTP), client.py (in-process or HTTP)
  common/   crypto.py (ES256, JWK thumbprints), dpop.py (proofs), money.py (integer cents, ZAR)
  bank/     authz.py (metadata, /par, /authorize, /token, /bc-authorize)
            api.py   (/api/accounts, /transactions, /payments, /beneficiaries)
            web.py   (sign-in, AI agents, approvals, ops)
            registry.py (AgentRegistry: StaticRegistry now, Veridact later)
            mcp.py   (reference bank MCP server: the enforcement point)
            known_assistants.py (Veridact known-assistant entries for Claude and other platforms)
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
| `VALET_POLICY_VERSION` | bank | unset | The bank's change reference for its policy, named on every receipt with the policy's hash. Unset: `unlabelled-<hash>`, and `/readyz` reports `labelled: false` |
| `VALET_EXTERNAL_ISSUERS`, `VALET_INTERNAL_SECRET` | bank | unset | Native mode: accept the bank IdP's tokens; let it register consents |
| `VALET_HANDOFF_SECRET`, `VALET_HANDOFF_IDPS` | bank | unset | Native mode: consent hand-off from the bank's IdP, and where results may be returned |
| `KAYA_CONNECT_VIA` | Kaya | unset | Native mode: the IdP's metadata URL; Kaya connects through it |

Limits live in `valet/bank/config.py`: token lifetimes (access 5 minutes, approval 5 minutes), maximum grant 90 days,
maximum monthly limit R5,000, at most 3 approvals waiting at once. Together with the profile version they form the policy document whose hash every receipt
carries (`GET /ops/policies`; [Technical design](docs/technical-design.md) §8.2).

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
- **A real payment system.** Valet never executes a payment; it instructs the bank's payments API. Here that is a
  fictional core in the same database (`valet/bank/core.py`). A bank writes an adapter that is idempotent on the
  payment intent id and runs reconciliation on a schedule (design section 5.1).
- **The real registry.** `StaticRegistry` stands in for Veridact.
- **IdP hooks for native mode beyond Keycloak.** Keycloak's is built and run; Auth0's and PingFederate's are not.
  The Keycloak extension's own limits are in its README.
- **Transport.** No TLS here; FAPI 2.0 requires it, and the bank would usually add mTLS or a gateway.
- **Full FAPI 2.0 conformance.** The direct API is FAPI 2.0-aligned (PAR, PKCE, DPoP, private_key_jwt, code binding
  to the agent's key) with conformance pending: it has not been through the OpenID conformance suite, and the known
  differences are listed in the design (section 14.1).

A bank does not have to adopt this code as it stands. It can run the reference components, or implement the
Valet profile on its own platform and prove it with the tests.

## Playground and doctor

**Playground.** Watch an agent reach a bank account without Valet, then with it, step by step, with what the bank
checked at each step. It also runs the doctor. Everything runs in an in-process demo bank, so it's safe to host:

```sh
uvicorn valet.apps.playground:get_app --factory --port 8003
```

**Doctor.** Check a bank's setup the way an agent will meet it: Poppy discovery and risk hints, the authorisation
server, keys, and the API and MCP server refusing what they must. It reads only public metadata and never signs in.

```sh
python -m valet.doctor https://bank.example     # a deployment
python -m valet.doctor --self-test              # the demo bank
```

## Licence

Apache License 2.0. See [LICENSE](LICENSE). The project's names are covered separately in [TRADEMARKS.md](TRADEMARKS.md).

## Governance and standards

Valet is run as an open project, not a one-person or one-company product. [GOVERNANCE.md](GOVERNANCE.md) sets out
how decisions are made and how contributors become maintainers, with the aim of maintainers from at least three
organisations and no single organisation holding a majority. Current maintainers are in [MAINTAINERS.md](MAINTAINERS.md).

The interoperable parts of the profile (mandate types, approval reasons, error codes and receipts) are being
standardised in the open as the IETF Internet-Draft
[draft-craig-oauth-rar-payment-mandates](https://datatracker.ietf.org/doc/draft-craig-oauth-rar-payment-mandates/).
Discussion happens on the IETF OAuth working group list (oauth@ietf.org), and anyone can join.

## Status

Version 0.1, a proof of concept. It is not production software and has not had an independent security review. See [SECURITY.md](SECURITY.md) to report a vulnerability and [CONTRIBUTING.md](CONTRIBUTING.md) to get involved.
