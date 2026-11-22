# Veridact agent identity profile: client attestation + SD-JWT VC

*Draft 0.1, 22 November 2026. Replaces the DID/W3C VC design. Author: Richard Craig. Status: design, not built;
`StaticRegistry` in the proof of concept stands in for Veridact.*

This document covers both lanes in the [MCP gateway design](mcp-gateway-design.md#two-lanes-into-the-bank):
§4.3 is how purpose-built agents (Lane B) prove themselves, and §4.5 is how Veridact vouches for mainstream
assistants (Lane A) that will never present an attestation.

> **Checked against:** draft-ietf-oauth-attestation-based-client-auth-12, draft-ietf-oauth-sd-jwt-vc-27,
> draft-ietf-oauth-client-id-metadata-document-03 and draft-ietf-oauth-status-list-21, on 22 November 2026.
> These are Internet-Drafts and can still change; re-check names when each becomes an RFC.

## 1. What Veridact answers

**Which agent is this, who operates it, and is it still trusted?** It is checked before a customer is asked to
grant anything, and it can be withdrawn across every organisation on the next request.

Valet answers the other question, *what did the customer allow?*, and does not change.

| Question | Product | Standard it rides on |
|---|---|---|
| Which software is this? | Veridact | Client ID Metadata Document (CIMD) |
| Who operates it, and are they verified? | Veridact | SD-JWT VC (operator credential) |
| Is this the real, current instance, holding its own key? | Veridact | Attestation-Based Client Authentication |
| Is it still trusted? | Veridact | Token Status List |
| Who is acting, on whose behalf, in the token? | Valet + Veridact | Actor profile (`act`, `sub_profile`) |
| What may it do? | Valet | RAR + `payment_mandate` draft |
| What happened? | Valet | Signed, chained receipts |

**One line:** Veridact proves who. Valet proves what's allowed. Receipts prove what happened.

## 2. Why we moved off DIDs

- Banks can verify an attestation at the token endpoint they already run. DIDs needed a separate resolver and
  verifier stack.
- The IETF OAuth working group has adopted every building block used here; the identity platforms Valet targets
  are implementing them.
- SD-JWT gives selective disclosure natively, so an operator proves "verified SA-registered business" without
  revealing anything else.
- The "Let's Encrypt for agents" idea maps directly: Veridact is an attester that verifies an operator once
  and stamps each agent instance with a short-lived attestation, the way an ACME CA stamps each server.

`did:web` can come back later as an optional identifier for customers who ask; nothing below depends on it.

## 3. Roles

| Role | Who | Holds |
|---|---|---|
| **Operator** | The organisation running the agent (e.g. Kaya Labs) | Operator credential; agent signing keys (ideally in a KMS or enclave) |
| **Agent instance** | One running agent | Its own key pair; a short-lived client attestation |
| **Veridact (attester and issuer)** | Run by Veridact, or by a consortium or a bank itself | Issuer keys, the status list, the operator register |
| **Relying organisation** | A bank, insurer or other deployer | Its own authorization server (any vendor) and Valet |

### Veridact has two halves

| Half | Where it runs | What it does |
|---|---|---|
| **Verifier** (sidecar) | Inside the bank, beside its authorization server (and callable by its MCP server and APIs) | Checks attestations, PoPs, CIMD documents and operator credentials; reads status from **locally cached** status lists. No outside call per request. |
| **Attester and status lists** | Outside the bank: run by Veridact, a consortium or a bank | Verifies operators, issues credentials and attestations, publishes status lists |

The verifier syncs the status lists on their `ttl` (5 minutes in the pilot), so a withdrawal reaches every bank
within one cache period. If the cache is older than its limit and can't be refreshed, the verifier fails closed
for payments and can still allow view-only access, by bank policy. The verifier is exposed to the bank's
components as a small local API; its result is passed to the Valet decision service as `context.veridact` in the AuthZEN request (the subject is always the customer)
(see [Decision service](decision-service.md)).

Any organisation can run its own Veridact attester. Relying organisations choose which attesters they trust,
exactly as browsers choose which CAs they trust. That keeps Veridact from becoming a single point of failure.

## 4. Artefacts

### 4.1 Client ID Metadata Document

The agent's `client_id` is an HTTPS URL, e.g. `https://agents.kaya.example/clients/money-assistant`, which
serves its OAuth client metadata (name, logo, redirect URIs, `jwks_uri`, contacts).

CIMD tells the bank *what the software says about itself*. It does **not** establish trust in the operator:
the draft leaves trust in the domain to the authorization server's own policies, and warns that self-asserted
`client_name` and `logo_uri` can be used for impersonation (§10.8, §10.10). That gap is what the operator
credential and attestation fill. The bank advertises support with `client_id_metadata_document_supported`. The
document's `client_id` must equal its URL, compared as a plain string with no normalisation; a client using
`private_key_jwt` must publish `jwks` or `jwks_uri`.

### 4.2 Operator credential (SD-JWT VC)

Issued once after operator verification, renewed yearly.

- `typ`: `dc+sd-jwt` (media type `application/dc+sd-jwt`)
- `vct`: `https://veridact.net/vct/agent-operator/v1` (the only claim the format requires)
- `iss`: Veridact's HTTPS issuer URL; keys published at `/.well-known/jwt-vc-issuer` (its `issuer` must equal
  `iss`; exactly one of `jwks_uri` or `jwks`). An `x5c` certificate chain is the alternative for banks that
  prefer X.509 trust anchors.
- `sub`: the operator's Veridact identifier
- `cnf`: the operator's key
- `status`: entry in Veridact's status list (§4.4)
- Selectively disclosable claims:
  - `legal_name`, `registration_number`, `jurisdiction` (e.g. `ZA`)
  - `verification_level` (`documentary`, `documentary+in-person`)
  - `regulated` (e.g. FSCA licence category, where applicable)
  - `client_ids`: the CIMD URLs this operator is allowed to run
  - `security_contact`

### 4.3 Client attestation (per agent instance)

Short-lived (minutes to hours), issued by Veridact to an agent instance after the operator authenticates with
its operator credential.

- JWT, `typ` `oauth-client-attestation+jwt`
- Required by the draft: `sub` (the agent's `client_id`, i.e. the CIMD URL), `exp` (short), `iat`, and
  `cnf.jwk` (the **instance's** public key)
- `iss`: the Veridact attester (optional in the draft; Veridact always sets it so banks can pick the trust anchor)
- Veridact extension claims:
  - `veridact_operator`: the operator's identifier, plus a digest of the operator credential
  - `status`: a status-list entry for this instance, so one compromised instance can be withdrawn without
    withdrawing the operator
  - `agent_class`: e.g. `ai_agent`, matching the actor profile's `sub_profile`

The agent sends it in the `OAuth-Client-Attestation` header, at PAR and at the token endpoint. Proof of
possession comes one of two ways, which the bank advertises in `token_endpoint_auth_methods_supported`:

| Method | Proof | Use |
|---|---|---|
| `attest_jwt_client_auth` | An `OAuth-Client-Attestation-PoP` JWT (`typ` `oauth-client-attestation-pop+jwt`; claims `aud`, `jti`, `iat`, optional `challenge`) | Agents that don't use DPoP |
| `attest_jwt_client_auth_dpop` | The DPoP proof doubles as the PoP ("combined mode") | **Lane B default:** one key, one proof, and the tokens are DPoP-bound |

The bank's authorization server can publish a `challenge_endpoint` (POST, returns `attestation_challenge`) for
freshness, and refuses with `use_attestation_challenge`, `use_fresh_attestation` or `invalid_client_attestation`.
The same headers work at a resource server, which answers with a `401` and the error in `WWW-Authenticate`.

### 4.4 Withdrawal (Token Status List)

Veridact publishes status list tokens (`typ` `statuslist+jwt`, media type `application/statuslist+jwt`), using
two bits per entry (the format allows 1, 2, 4 or 8). Each credential points to its entry with
`"status": {"status_list": {"idx": <n>, "uri": "<list URL>"}}`, and each list carries a `ttl` in seconds:

| Value | Meaning | Effect at the bank |
|---|---|---|
| `0x00` VALID | Trusted | Proceed |
| `0x01` INVALID | Withdrawn permanently | Refuse; Valet pauses every grant held by this agent |
| `0x02` SUSPENDED | Under investigation | Refuse new grants; Valet holds payments for approval |

The same lists carry the status of known-assistant entries (§4.5).

Lists are large and shared across operators for herd privacy. A short `ttl` (5 minutes in the pilot) means a
withdrawal takes effect across every bank within one cache period. The status list can later be fed by Shared
Signals (CAEP) for push rather than poll.

### 4.5 Known-assistant entry (Lane A)

Mainstream assistants (Claude, ChatGPT, Gemini, Copilot) connect as one OAuth client per platform and will not
request Veridact attestations. Veridact verifies the platform operator itself and issues a credential *about*
the platform, which the bank's gateway checks. The platform does nothing.

- SD-JWT VC, `vct` `https://veridact.net/vct/known-assistant/v1`
- `sub`: the platform's Client ID Metadata Document URL or URLs, or a stable platform identifier where the
  platform uses a client the bank registers (Gemini, Copilot)
- Claims: `operator` (legal name, jurisdiction, verification date), `redirect_hosts`, `token_endpoint_auth`,
  `published_egress`, `max_level`
- `status`: a status-list entry, so withdrawal stops that assistant at every Valet bank on the next call

The field list and how the gateway uses each one are in the
[MCP gateway design](mcp-gateway-design.md#veridact-known-assistant-entries). The credential identifies the
platform, never a user or an instance, so it never raises the assurance tier above Approved payer.

**Fairness.** A platform must be able to see its own entry, be told before a withdrawal where possible, and
dispute it. A shared kill switch that can switch off an assistant at every bank needs public rules for when it
is used.

## 5. Flow with Valet (Lane B)

1. **Register once.** The operator is verified by Veridact and receives the operator credential.
2. **Start an instance.** The instance generates a key and gets a client attestation bound to it.
3. **Connect.** The agent sends PAR to the bank with the attestation, a PoP and the DPoP key. The bank's
   authorization server checks:
   - the attestation's signature against a trusted attester's keys
   - the CIMD document matches `sub`
   - the operator and instance status entries are VALID
   - the bank's own admission policy, e.g. "SA-registered, documentary+in-person"
4. **Consent.** Valet shows the customer the verified operator name (from the disclosed credential claims),
   not just the name the agent claims for itself.
5. **Tokens.** The access token carries the customer as `sub` and the agent in `act`
   (`iss` = Veridact attester, `sub` = client_id, `sub_profile` = `ai_agent`), bound by `cnf` to the DPoP key.
6. **Every call.** Valet's checks run as today, plus a status re-check on a short cache.
7. **Withdrawal.** Veridact flips the status bit; on the next call every bank refuses, and Valet pauses the
   agent's grants and writes a receipt citing the status change.

## 6. What changes in the Valet code

| Area | Change |
|---|---|
| `StaticRegistry` | Replace with a `VeridactAttestationVerifier`: validate attestation + PoP, fetch and cache CIMD and the status list |
| Consent screen | Show disclosed `legal_name`, `jurisdiction` and `verification_level` |
| Tokens | Add the `act` claim per the actor profile |
| Receipts | Record the attester, the operator credential digest and the status seen at decision time |
| Keycloak extension | Client authenticator for attestation-based client auth |
| Tests | Valid/withdrawn/suspended operator and instance; unknown attester; CIMD mismatch; stale status list |

## 7. Pilot cut (90 days)

- One Veridact attester (af-south-1), manual operator verification, one status list.
- Keycloak first, then PingFederate.
- Out of scope: multiple attesters, CAEP push, did:web, cross-border recognition.

## 8. Open questions

1. Who runs the attester in production: Veridact alone, a bank consortium, or both (multi-attester from day one)?
2. Operator verification level for the pilot: documentary only (CIPC registration) or documentary + in-person?
3. Does a bank want to admit operators by policy (e.g. any SA-registered company), or by explicit allow-list?
4. Who decides when a known-assistant entry is withdrawn, and what notice the platform gets?
5. Should Veridact register its own `vct` type metadata and the `veridact_operator` claim with IANA via a short
   companion Internet-Draft, so other attesters can issue the same credential?

## 9. References

- draft-ietf-oauth-attestation-based-client-auth
- draft-ietf-oauth-client-id-metadata-document
- draft-ietf-oauth-sd-jwt-vc; RFC 9901 (SD-JWT)
- draft-ietf-oauth-status-list
- draft-mcguinness-oauth-actor-profile
- draft-ietf-wimse-aims
- draft-craig-oauth-rar-payment-mandates
