# `veridact.net/valet`: a banking extension for the Personal Agent Protocol

Draft, version 1 · 26 November 2026 · Aligned to Poppy 1.1 (draft), and works with 1.0 agents. Not registered with
Poppy; offered to the Poppy authors as input to their roadmap items "Signed approvals" and "Payments". Built in the
proof of concept: discovery and the OAuth metadata behind it, scope-only sign-in, sign-out, CIMD agents with identity
tiers, scope hints, and verified Sessions in receipts (`valet/bank/poppy.py`, `valet/bank/cimd.py`,
`tests/test_poppy.py`, `tests/test_cimd.py`). Not built: the operations flow in §3.2. What Valet does for each
Poppy 1.1 rule that applies to a bank is in §8.

## Summary

The Personal Agent Protocol (Poppy) gets a personal agent through a company's front door: discovery, the agent's
identity, sign-in, Sessions, APIs and conversations. Its `operations` extension (version 3) already lets a company
ask for approval of **one exact action**, and guarantees it is performed at most once.

Banks need three more things. Poppy leaves all three out on purpose:

| Gap in Poppy 1.1 | What Poppy says | What this extension adds |
|---|---|---|
| Limits the company holds | Agent approvals rest on "an instruction the User gave the Personal Agent", held by the agent (operations §5) | **Standing mandates held by the bank**: payees, per-payment cap, monthly amount and count, expiry. Inside them, the bank performs the payment without an operation. |
| Approval the company sees | "For an action where it wants to see the User approve, it doesn't return operations, and has the User confirm on its own website or in its app … This extension doesn't define that step" (operations §8.1) | **Approval in the bank's app**: the bank returns an operation the agent may not approve, the customer approves in the bank app, and the agent retries. |
| Evidence | Not described | **Receipts**: a signed, chained record of every decision, naming the Poppy Session, operation and approval reference |

It also uses two things Poppy already has: scope hints, and the Session ID.

The rule underneath is the same as Valet's everywhere: **the limits live at the bank, not in the agent.** An agent
that has been talked into overspending still can't.

## 1. Advertising support

A bank lists the extension in `poppy.json` (Poppy §3.3). It requires `operations` version 3:

```json
"extensions": {
  "operations": [{ "version": "3" }],
  "veridact.net/valet": [{
    "version": "1",
    "profile": "valet-profile/0.8",
    "levels": ["view_only", "approved_payer", "bill_payer"],
    "authorization_details_types": ["valet_accounts", "valet_payments", "valet_payment_once"],
    "approval_channels": ["bank_app"],
    "receipts": { "format": "valet-receipt+jwt", "keys": "https://bank.example/jwks" }
  }]
}
```

The extension also says how a plain Poppy scope becomes a mandate (`scope_levels`, §2) and how the bank knows the
agent (`agent_identity`, §2.1):

```json
"scope_levels": { "accounts:read": "view_only", "payments:approve-each": "approved_payer",
                  "payments:standing": "bill_payer" },
"agent_identity": {
  "cimd":     { "supported": true, "max_level": "approved_payer" },
  "veridact": { "supported": true, "max_level": "bill_payer", "spec": "https://veridact.net/docs/veridact/spec/" }
}
```

An agent declares it with `Poppy-Extensions: "operations";v="3", "veridact.net/valet";v="1"`. A bank that won't
move money for an agent without it refuses payment requests with `extension_required` (Poppy §3.3).

### 1.1 The discovery chain

A Poppy agent trusts the issuer `poppy.json` names only when the two sides point at each other (Poppy §3). The bank
serves both halves:

| Document | Says |
|---|---|
| `/.well-known/poppy.json` | `auth.issuer`: Valet's authorisation server, and `organization.domain`: the bank's host |
| `/.well-known/oauth-protected-resource` (RFC 9728) | `resource`: the bank's domain; `authorization_servers`: the same issuer; DPoP-bound tokens required |
| `/.well-known/oauth-authorization-server` (RFC 8414) | `protected_resources` lists the domain back; `revocation_endpoint`, `grant_types_supported` with `refresh_token`, `scopes_supported`, `token_endpoint_auth_signing_alg_values_supported` (`ES256`, `PS384`), `authorization_details_types_supported` and `client_id_metadata_document_supported` |

The MCP server keeps its own path-inserted document (`/.well-known/oauth-protected-resource/mcp`), whose `resource`
is the MCP URL, as MCP clients expect.

## 2. Scopes and hints

Valet's access levels are offered as scopes, with Poppy's risk hints (Poppy §4.7):

| Scope | Valet level | `changes` | `personal_data` |
|---|---|---|---|
| `accounts:read` | View only | `none` | `true` |
| `payments:approve-each` | Approved payer | `irreversible` | `true` |
| `payments:standing` | Bill payer | `irreversible` | `true` |

A scope is only the agent's request. As in every Valet flow, **the customer builds the mandate on the bank's own
consent screen** during Poppy Direct Sign-In (Poppy §4.2). They choose the accounts, payees, limits and expiry. The
bank stores the mandate as Valet `authorization_details` (Valet profile §3), and the access token carries the grant id.

So an agent needs nothing Valet-specific to connect. It pushes an ordinary request (PAR, as the server metadata
requires) with a `scope` and no `authorization_details`. The bank turns the scope into the matching level's
template, and the customer completes it. An agent that also sends `authorization_details` gets the same flow with
more control over what is preselected. Unknown scopes are refused with `invalid_scope`; `offline_access` is accepted
and changes nothing.

**Never more than was asked for** (Poppy §4.7). Each level includes the powers of the levels below it, so it implies
their scopes: View only implies `accounts:read`; Approved payer adds `payments:approve-each`; Bill payer adds
`payments:standing`. A grant gives the chosen level's scopes **that the agent asked for**, and no others. So the
consent screen offers only the levels, up to the highest one asked for, that grant at least one requested scope, and
lists under each what it will grant (Poppy §10.8). The token response's `scope` is what was granted.

| Agent asks for | Customer can choose | Granted `scope` |
|---|---|---|
| `accounts:read` | View only | `accounts:read` |
| `accounts:read payments:approve-each payments:standing` | Any level (a CIMD agent: up to Approved payer) | The chosen level's scopes |
| `payments:standing` | Bill payer only | `payments:standing` |

An agent should ask for every scope it could use. A CIMD agent that asks only for `payments:standing` can only be
declined, because its tier stops at Approved payer and Approved payer grants nothing it asked for.

Valet's own agents can still ask with `authorization_details` alone, with no `scope`. That's this extension's
request form (Poppy §3.3); the grant then reports all of its level's scopes.

Valet offers Direct Sign-In only. It does not offer Device Sign-In (the device authorization grant): a code the
customer types on another screen is the pattern device-code phishing exploits, and a bank shouldn't switch it on to
admit agents.

### 2.1 Agent identity tiers

How much an agent may do depends on how well the bank knows it:

| Tier | The bank knows | Highest level |
|---|---|---|
| CIMD | The agent's `client_id` is an HTTPS URL on a domain the bank approves, serving its metadata and keys (draft-ietf-oauth-client-id-metadata-document). It authenticates with `private_key_jwt`, using those keys | Approved payer: the customer approves every payment in the bank app |
| Veridact | The same URL, plus a Veridact credential naming the operator ([Veridact agent identity](veridact-agent-identity.md)) | Bill payer |

The ceiling is enforced three times: the consent screen doesn't offer a level above it, the grant service refuses
one, and every payment is checked against the agent's tier at that moment. If a Veridact credential is withdrawn
while the domain stays approved, the agent's existing Bill payer grant still works, but every payment goes back to
the customer (reason `approved_payer`).

The approved-domain list is read on every call. Taking a domain off it stops that agent's live grants on its next
request, not only new connections. The bank never fetches a metadata document from a domain it hasn't approved.


## 3. Payments: three outcomes

The agent makes an ordinary payment request (API or MCP). The bank checks it against the mandate in the profile's
fixed order (Valet profile §3), and answers in one of three ways.

### 3.1 Inside the mandate: performed

The bank performs the payment, at most once per `Idempotency-Key` (Valet technical design §5.1). It responds as
usual, with the receipt:

```json
{ "status": "paid", "payment_id": "pay_…", "receipt": { "seq": 4812, "hash": "sha256:…" } }
```

There is no operation and no approval, because the customer approved the standing mandate in advance, at the bank.
This is what Poppy's agent approvals try to do, with the difference that the bank, not the agent, holds the rule.

### 3.2 Outside the mandate: an operation the customer approves in the bank app

The bank returns a Poppy operation (operations §4) and holds the payment. The extension adds a `veridact.net/valet`
member to the operation:

```json
HTTP/1.1 403 Forbidden

{
  "error": "approval_required",
  "operation": {
    "operation_id": "pay_8Hq2",
    "revision": "1792483200-r7Kd",
    "summary": "Pay **R2,400.00** to **City of Joburg Water** from Cheque account ••4821.",
    "terms": { "from": "acc_4821", "to": "ben_coj_water", "amount": { "amount": "2400.00", "currency": "ZAR" } },
    "expires_at": "2026-11-22T14:20:00+02:00",
    "extensions": {
      "veridact.net/valet": {
        "approve_in": "bank_app",
        "reason": "over_per_payment",
        "status_endpoint": "https://api.bank.example/valet/approvals/pay_8Hq2"
      }
    }
  }
}
```

- **`approve_in: "bank_app"`** means the agent **must not** send its own approval (`approver` `user` or `agent`).
  The bank has already asked the customer in its app (push, or CIBA, Valet technical design §6). An agent approval
  sent anyway is declined (operations §6).
- **`reason`** is one of the profile's seven reasons. Poppy's operations extension deliberately has no reason
  codes, because codes "would reveal the Company's risk rules". These reasons are different in kind: they name
  which of the **customer's own** limits the payment fell outside. The Session can already see those limits,
  because they are the customer's mandate, which satisfies Poppy's rule that `reason` reveals nothing the Session
  couldn't see. The bank's own fraud and risk rules are never given as reasons; a payment they stop is declined
  without one.
- The agent polls `status_endpoint` (`pending`, `approved`, `declined`, `expired`), honouring `Retry-After`.
- When it is `approved`, the agent sends the same request again with:

  ```
  Poppy-Approval: operation_id="pay_8Hq2", revision="1792483200-r7Kd", approver="company"
  ```

  `approver="company"` is the value this extension adds to Poppy's `user` and `agent`. It says the bank recorded
  the approval itself, so the bank checks its own record, not the agent's statement. Then operations §6's checks
  and §7's at-most-once rule apply unchanged.

This gives Poppy's roadmap item "signed approvals" a working form for banks today. The approval is made on the
customer's device, inside an app the bank controls, and recorded by the bank, so the bank can verify it itself
(operations §8.1).

### 3.3 Refused

Some payments can't be approved at all, such as a payee the customer never saved, or a paused mandate. These are
refused with Poppy's `approval_declined` (operations §6) or an ordinary error, with no operation. The plain-language
`reason` follows Poppy's rule.

## 4. Receipts and the Session

Every decision becomes a signed, hash-chained receipt at the bank: performed, held, approved, declined, refused,
unknown (Valet technical design §8). With this extension, each receipt also records:

| Field | From |
|---|---|
| `session.sid`, `session.iss`, `session.sub` | The Poppy Session JWT (Poppy §5.2) |
| `session.verified` | Whether the bank verified the Session JWT and its delegation against the agent's registered keys |
| `operation_id`, `revision` | The operation, when there was one |
| `approval.approver`, `approval.reference` | `company` for bank-app approvals; Poppy's `reference`, when an agent sends one |

So a dispute can follow one continuous Session across reads, the held payment, the approval and the result.

A Session never grants anything: access comes only from the token and the mandate. As Poppy §5.3 requires, a request
whose Session header fails verification is refused with `invalid_session` (HTTP 400), and one without a
`Poppy-Version` the bank serves (1.0 or 1.1) with `version_unsupported`. So every Session in a receipt is a verified
one, with the version it used. A request without a Session header goes on as before: Valet records a Session, but
never needs one. If the bank's agent registry can't be reached, the request is judged on its token and mandate and
the Session isn't recorded.

The agent can fetch the receipts that concern its own grant. They are verifiable with the bank's published keys
(`receipts.keys` in §1).

## 5. Stopping

The agent signs out by revoking its refresh token at `revocation_endpoint` (RFC 7009, Poppy §4.6). A grant has one
refresh token at a time, so this disconnects the grant, exactly as if the customer had, and its access tokens stop
with it. The receipt records that the agent signed out. An agent the bank no longer trusts can still sign out.

The customer can disconnect or pause in the bank app at any time. This revokes the Poppy refresh tokens (Poppy
§4.6), pauses the mandate, and cancels held payments that haven't reached the bank, all recorded in receipts. The
bank's denylist and Veridact withdrawal work as in Valet (Valet technical design §9.1).

## 6. Security considerations

- The bank must not return an operation with `approve_in: "bank_app"` unless it has actually asked the customer.
  Otherwise the agent waits on an approval that will never come.
- `approver="company"` is meaningful only to the bank that returned the operation. Another company receiving it
  treats it as an unknown approver value and declines.
- Reasons reveal the customer's own mandate to the agent acting under it. A bank that considers even that too much
  for a level can send `reason` only to agents at a higher assurance tier.
- Everything in Poppy §10 and operations §8 applies.

## 7. Open questions for the Poppy authors

1. Should `approver="company"` be added to the `operations` extension itself, as the way a company records an
   approval made in its own app? That would close the gap in operations §8.1 for every company, not just banks.
2. Is a standing mandate held by the company something Poppy wants in `operations`, or as a separate extension?
3. Should reasons limited to the user's own limits be allowed in `operations`, under the existing rule that a
   `reason` reveals nothing the Session couldn't see?
4. Is there interest in a shared receipt format, so evidence reads the same across companies?

## 8. Poppy 1.1 conformance

What Valet does for each Poppy 1.1 rule that applies to a bank. Conversations (§8), web browsing (§6) and task
coverage (§9) don't: Valet has no Company Agent, no website for agents to browse, and no tasks endpoint.

| Poppy 1.1 | Valet |
|---|---|
| §3: `poppy.json`, `organization.domain` is the serving host | Served; `protocol_version` `1.1` |
| §3.2: domain protected resource metadata; issuer lists the domain in `protected_resources` | Both served (§1.1) |
| §3.2: `revocation_endpoint`, `grant_types_supported` with `refresh_token` | `/revoke`; listed |
| §3.4: `Poppy-Version` checked where Sessions are verified; `version_unsupported` | 1.0 and 1.1 accepted; others refused |
| §4.1: `client_id` is a CIMD URL; `jwks_uri` and `redirect_uris` on its host (or loopback) | Enforced for CIMD agents (`cimd.py`). Valet's registered demo agents use short client ids, which a 1.1 agent never would |
| §4.1: `private_key_jwt`, `aud` the issuer as one string, `exp` up to 5 minutes | Enforced; a list or the token endpoint as `aud` is refused |
| §4.1, §5.2: accept `ES256` and `PS384` assertions and delegations | Both; the key type fixes the algorithm (P-256: ES256; RSA, 2048 bits or more: PS384) |
| §4.2: Direct Sign-In with PKCE, PAR when required, `iss` on the redirect, exact `redirect_uri`, loopback on any port | All; PAR is required. The consent page is shown on every request, so `prompt=consent` changes nothing |
| §4.3: Device Sign-In | Not offered, on purpose (§2) |
| §4.4: refresh tokens; DPoP key kept across refreshes | Rotated with a short retry window, bound to the DPoP key from consent. A `scope` sent at refresh to narrow access is ignored: the token keeps the grant's scope |
| §4.5: a `resource` the bank doesn't serve to agents gets `invalid_target` | The bank's domain only. The MCP server takes tokens from the bank's IdP, issued to AI platforms, so Poppy agents use the API |
| §4.7: `scope` required, unknown ones `invalid_scope`, never more than requested, at least one granted | As above (§2). Valet's own agents may use `authorization_details` instead (§2) |
| §5.2, §5.3: Session JWT and delegation checks; delegation key by `kid`; `ath` present exactly when a token is | All; failures are `invalid_session` |
| §5.3 step 3: the access token issued to the Session's `client_id` | Checked |

## References

- [Personal Agent Protocol 1.1](https://personalagentprotocol.org/docs/1.0/spec) and its
  [operations extension](https://personalagentprotocol.org/docs/extensions/operations)
- [Valet profile](valet-profile.md), [Technical design](technical-design.md)
- [draft-craig-oauth-rar-payment-mandates](https://datatracker.ietf.org/doc/draft-craig-oauth-rar-payment-mandates/)
