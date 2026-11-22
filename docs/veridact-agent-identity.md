# How Valet uses Veridact for agent identity

*Draft 0.2, 22 November 2026. Status: design, not yet built; `StaticRegistry` in the proof of concept stands in for
Veridact.*

**The Veridact specification is the source of truth for every Veridact format, protocol and check.** This document
only says how Valet uses it, so the two can't drift. Where a detail here and the Veridact specification disagree,
the specification wins and this document is wrong.

- Specification: [Veridact specification v0.4](https://github.com/veridactlabs/veridact/blob/main/docs/specification.md)
- Direction: [v0.5 proposal: SD-JWT VC, OAuth-native identifiers and known assistants](https://github.com/veridactlabs/veridact/blob/main/docs/proposals/0.5-sd-jwt-vc.md)
  (proposed). This document is written against v0.5.

## What each product answers

| Question | Product |
|---|---|
| Which agent is this, who operates it, and is it still trusted? | Veridact |
| What did the customer allow? | Valet |
| What happened? | Valet's receipts |

Veridact never holds customer identities, and Valet never decides who an operator is.

## Where the pieces run

| Piece | Where | Owned by |
|---|---|---|
| Veridact verifier (the `veridact-sidecar`, `/v1/challenge` and `/v1/verify`) | Inside the bank, beside its authorisation server; callable by its MCP server and APIs | The bank runs it |
| Veridact issuer, status lists, transparency log, trust list | Outside the bank | An accredited issuer and the governance authority |
| Valet decision service | Inside the bank, beside its MCP server and APIs ([Decision service](decision-service.md)) | The bank runs it |

The bank's components never call an issuer. The verifier reads cached public files.

## Lane A: mainstream assistants

Claude, ChatGPT, Gemini and Copilot connect as one OAuth client per platform, and will never hold a Veridact
credential. Instead, Veridact issues a **known-assistant entry** about each platform (Veridact v0.5 proposal, §6).
The bank uses it three ways:

- **Admission.** At client registration and on every token request, the bank's authorisation server maps the
  client (its CIMD URL, or the client the bank registered for that platform) to a valid entry, through the
  verifier.
- **Consent screen.** Valet shows the verified operator name from the entry ("Claude, operated by Anthropic PBC"),
  never the name the client gives itself.
- **Kill switch.** A withdrawn or suspended entry stops the assistant at every bank on its next check. Valet pauses
  the affected mandates, and records the status that caused it in a receipt.

An entry never raises the tier, so Lane A stops at Approved payer ([MCP gateway design](mcp-gateway-design.md)).

## Lane B: purpose-built agents

The agent's `client_id` is its Veridact identifier: a CIMD URL whose `jwks` holds its key (v0.5 §1.1). It proves
itself one of two ways:

| Veridact pattern | At the bank | When |
|---|---|---|
| **C. Client attestation** (v0.5 §5.3) | `attest_jwt_client_auth_dpop` at PAR and the token endpoint: the Veridact-issued Client Attestation plus the DPoP proof | **Default**, where the bank's authorisation server supports attestation-based client authentication |
| **A. Token exchange** (v0.5 §5) | The SD-JWT+KB presentation as `subject_token`, with DPoP | Where it doesn't, through the Keycloak bridge or an equivalent |

Either way, the bank's authorisation server asks the verifier and issues Valet's DPoP-bound token. Per Veridact
§5.4, that token carries:

- the customer in `sub`
- the agent URL in `act.sub`, with `sub_profile` `ai_agent`
- `veridact.tier`, `veridact.limits` and the credential ids
- `valet_grant`, the mandate

Lane B can earn Bill payer.

## What Valet does with Veridact's answer

The verifier's result reaches the Valet decision service as `context.veridact` in each AuthZEN request
([Decision service](decision-service.md)). Valet uses it three ways:

1. **Limits: the lower of the two applies.** The operator's delegation limits (`per_payment`, `per_day`) and the
   customer's mandate both apply, and Valet holds a payment against whichever is lower. `per_day` is the
   operator's budget for that agent at this bank, across every customer it serves. Valet counts it against the
   agent URL, as Veridact's spec requires the relying party to do.
2. **Decisions:** Veridact's results map onto Valet's outcomes as follows.

   | Veridact decision and code | Valet outcome |
   |---|---|
   | `allow` | Valet's own mandate checks run |
   | `deny`: `AUTH_FAILED`, `ISSUER_UNTRUSTED`, `TIER_TOO_LOW`, `OPERATOR_NOT_ALLOWED` | `agent_untrusted` (403) |
   | `deny`: `SCOPE_NOT_HELD` | `declined`, reason `not_permitted` |
   | `ask_person`: `LIMIT_PER_PAYMENT`, `LIMIT_PER_DAY` | `approval_required`, reason `over_operator_limit` (proposed for Valet profile 0.9) |
   | `challenge`: `CHALLENGE_REQUIRED` | `401`; the agent fetches a new nonce |
   | `VERIFICATION_UNAVAILABLE` | `registry_unavailable`: payments fail closed at once; reads may use the last good result for one cache period |

3. **Receipts:** each receipt records the issuer, the Agent Credential id, the tier and the status seen when the
   decision was made.

## How long a withdrawal takes

| Path | Worst case |
|---|---|
| Bank denylist (`/ops/denylist`) | Next request; no cache |
| Veridact withdrawal | Up to 5 minutes for Veridact to publish it, plus up to 5 minutes in the verifier's cache, plus Valet's 60-second registry cache: **about 11 minutes** |
| Bank's own registry (PoC `StaticRegistry`) | 60 seconds |

For an incident, the bank uses its denylist. Veridact withdrawal is the network-wide path, not the emergency brake.

## What changes in the Valet code (when built)

| Area | Change |
|---|---|
| `StaticRegistry` | Joined by a `VeridactRegistry` that calls the verifier sidecar |
| Consent screen | Operator name, jurisdiction and tier from the verified credential or known-assistant entry |
| Tokens | `act` and the `veridact` claim, per Veridact §5.4 |
| Mandate checks | Veridact delegation limits, including `per_day` per agent |
| Receipts | Issuer, credential id, tier and status at decision time |
| Keycloak extension | Client authenticator for attestation-based client authentication (pattern C) |
