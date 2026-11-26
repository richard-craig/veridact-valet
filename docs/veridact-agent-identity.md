# How Valet uses Veridact for agent identity

*Draft 0.3, 22 November 2026. Status: Lane A is built (known-assistant checks in `valet/bank/known_assistants.py`).
Lane B is design: the `VeridactRegistry` and pattern C are not built yet, and `StaticRegistry` stands in for them.*

**The Veridact specification is the source of truth for every Veridact format, protocol and check.** This document
only says how Valet uses it, so the two can't drift. Where a detail here and the Veridact specification disagree,
the specification wins and this document is wrong.

- Specification: [Veridact specification v0.5](https://github.com/veridactlabs/veridact/blob/main/docs/specification.md) (draft; also at
  [veridact.net/docs](https://veridact.net/docs/veridact/spec/)). This document is written against it, and section
  numbers below are the specification's.
- Background: [the v0.5 proposal](https://github.com/veridactlabs/veridact/blob/main/docs/proposals/0.5-sd-jwt-vc.md) (accepted).

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
credential. Instead, Veridact issues a **known-assistant entry** about each platform ([Veridact §13](https://github.com/veridactlabs/veridact/blob/main/docs/specification.md#13-known-assistants)).
The bank uses it three ways:

- **Admission.** At client registration and on every token request, the bank's authorisation server maps the
  client (its CIMD URL, or the client the bank registered for that platform) to a valid entry, through the
  verifier.
- **Consent screen.** Valet shows the verified operator name from the entry ("Claude, operated by Anthropic PBC"),
  never the name the client gives itself.
- **Kill switch.** A withdrawn or suspended entry stops the assistant at every bank on its next check. Valet pauses
  the affected mandates, and records the status that caused it in a receipt. How soon "next check" comes is
  bounded by the status list: Veridact publishes a change within 5 minutes and verifiers cache for at most 5
  ([§14.1](https://github.com/veridactlabs/veridact/blob/main/docs/specification.md#141-token-status-list)), so network-wide it is minutes, not seconds. To stop an assistant
  at once, the bank uses its own denylist.

An entry never raises the tier, so Lane A stops at Approved payer ([MCP gateway design](mcp-gateway-design.md)).

## The CIMD baseline (built)

Before Veridact, there is CIMD. An agent whose `client_id` is an HTTPS URL serving its client metadata can connect
from any domain the bank approves (`VALET_CIMD`, `valet/bank/cimd.py`), with no registration. It authenticates with
`private_key_jwt`, using the keys in its own document. The bank knows only which domain runs it, so:

- the consent screen names the domain, not the agent's self-chosen name, and says "Not verified by Veridact";
- the agent can be at most **Approved payer**, enforced at consent and again on every payment;
- the approved list is checked on every call, so taking a domain off it stops the agent's live grants at once.

Lane B adds Veridact to the **same URL**. A verified CIMD agent is on the Veridact tier and can earn Bill payer. If
its credential is withdrawn while its domain stays approved, it drops back to the CIMD tier, and every payment under
an existing Bill payer grant goes back to the customer for approval. In the proof of concept, a trust-file entry
marked `verified` stands in for the credential.

## Lane B: purpose-built agents

The agent's `client_id` is its Veridact identifier: a CIMD URL whose `jwks` holds its key ([§5.1](https://github.com/veridactlabs/veridact/blob/main/docs/specification.md#51-agents-are-oauth-clients)). It proves
itself one of two ways:

| Veridact pattern | At the bank | When |
|---|---|---|
| **C. Client attestation** ([§10.3](https://github.com/veridactlabs/veridact/blob/main/docs/specification.md#103-pattern-c-client-attestation)) | `attest_jwt_client_auth` at PAR and the token endpoint: the Veridact-issued Client Attestation, with a DPoP proof as its proof of possession so the same key binds the access token | **Default**, where the bank's authorisation server supports attestation-based client authentication |
| **A. Token exchange** ([§10.2](https://github.com/veridactlabs/veridact/blob/main/docs/specification.md#102-patterns-a-and-b)) | The SD-JWT+KB presentation as `subject_token`, with DPoP | Where it doesn't, through the Keycloak bridge or an equivalent |

Either way, the bank's authorisation server asks the verifier and issues Valet's DPoP-bound token. Per Veridact
[§10.4](https://github.com/veridactlabs/veridact/blob/main/docs/specification.md#104-access-tokens), that token carries:

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
| Tokens | `act` and the `veridact` claim, per Veridact [§10.4](https://github.com/veridactlabs/veridact/blob/main/docs/specification.md#104-access-tokens) |
| Mandate checks | Veridact delegation limits, including `per_day` per agent |
| Receipts | Issuer, credential id, tier and status at decision time |
| Keycloak extension | Client authenticator for attestation-based client authentication (pattern C) |
