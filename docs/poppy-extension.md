# `veridact.net/valet`: a banking extension for the Personal Agent Protocol

Draft, version 1 · 22 November 2026 · Not registered with Poppy; offered to the Poppy authors as input to their
roadmap items "Signed approvals" and "Payments". Built in the proof of concept: discovery, scope hints and Session
IDs in receipts (`valet/bank/poppy.py`, `tests/test_poppy.py`). Not built: everything under "Operations" below.

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

An agent declares it with `Poppy-Extensions: "operations";v="3", "veridact.net/valet";v="1"`. A bank that won't
move money for an agent without it refuses payment requests with `extension_required` (Poppy §3.3).

## 2. Scopes and hints

Valet's access levels are offered as scopes, with Poppy's risk hints (Poppy §4.7):

| Scope | Valet level | `changes` | `personal_data` |
|---|---|---|---|
| `accounts:read` | View only | `none` | `true` |
| `payments:approve-each` | Approved payer | `irreversible` | `true` |
| `payments:standing` | Bill payer | `irreversible` | `true` |

A scope is only the agent's request. As in every Valet flow, **the customer builds the mandate on the bank's own
consent screen** during Poppy Direct or Device Sign-In (Poppy §4.2, §4.3). They choose the accounts, payees,
limits and expiry. The bank stores the mandate as Valet `authorization_details` (Valet profile §3), and the access
token carries the grant id.

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

A Session never grants anything: access comes only from the token and the mandate. An unverifiable Session is still
recorded, marked `verified: false` with the reason, so a forged or broken header leaves evidence and opens no door.

The agent can fetch the receipts that concern its own grant. They are verifiable with the bank's published keys
(`receipts.keys` in §1).

## 5. Stopping

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

## References

- [Personal Agent Protocol 1.1](https://personalagentprotocol.org/docs/1.0/spec) and its
  [operations extension](https://personalagentprotocol.org/docs/extensions/operations)
- [Valet profile](valet-profile.md), [Technical design](technical-design.md)
- [draft-craig-oauth-rar-payment-mandates](https://datatracker.ietf.org/doc/draft-craig-oauth-rar-payment-mandates/)
