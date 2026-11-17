# The Valet profile

**Version `valet-profile/0.7` (17 November 2026).** The shared permission standard every Valet deployment implements: the access levels, the approval rules, the check order on every call, the error codes and the receipt format. One agent integration then works at every organisation that runs Valet.

The profile is what the Valet project defines. Each bank decides which levels, accounts, limits and grant lengths it offers, within the profile (Technical design §1.2). The code reports the profile version it implements in every policy document (`valet/bank/policy.py`, `PROFILE_VERSION`), so every receipt names the rules it was checked against.

Status marks:
- **Built**: in the proof of concept and covered by tests.
- **Specified**: part of the profile, not yet built (Technical design §3.1).

## 1. Permission types

Permissions travel as OAuth Rich Authorization Requests (RFC 9396, `authorization_details`), so the mandate the customer approves and the grant the bank enforces are one record.

| Type | What it carries | Status |
| --- | --- | --- |
| `valet_accounts` | Read access: `actions` (`read_balances`, `read_transactions`), `accounts`, `history_days` | Built |
| `valet_payments` | A standing payment mandate: `actions` (`pay_existing_beneficiary`), `accounts`, `limits`. Specified additions: `payees`, `limits.per_payment`, `limits.per_month.count` and `approval` | Built (monthly limit). Specified (the rest) |
| `valet_payment_once` | Exactly one payment, valid for one action only: `from`, `to` (name and account), `amount`, `reference`. The bank offers it when a payment needs approval; the agent never invents one | Built |

In AP2 terms, `valet_payments` is an open mandate and `valet_payment_once` is a closed one.

## 2. Access levels

Levels are named templates over the types. The agent may ask for a level. The customer chooses on the consent screen, and the grant records what the customer chose, never what the agent asked for (`valet/bank/levels.py`).

| Level | Code | Types | The agent may | The agent may never | Status |
| --- | --- | --- | --- | --- | --- |
| **View only** | `view_only` | `valet_accounts` | See balances and 90 days of transactions on the chosen account | Move money, add beneficiaries, change limits, see card numbers or passwords | Built |
| **Approved payer** | `approved_payer` | `valet_accounts` + `valet_payments` | Prepare payments to the mandate's payees. **Every payment is approved by the customer in the bank app.** Pilot default for anything that moves money | Pay without the customer's approval, add beneficiaries, change limits | Specified |
| **Bill payer** | `bill_payer` | `valet_accounts` + `valet_payments` | Pay the mandate's payees within the limits without asking each time | Pay someone new without asking, add beneficiaries, change limits | Built (monthly limit). Specified (payees, cap, count) |

## 3. Approval rules

These are the named constraints on a `valet_payments` mandate. Each one appears in the mandate, on the consent screen, and on every receipt for the grant.

| Constraint | Field | Rule | Status |
| --- | --- | --- | --- |
| **Accounts** | `accounts` | The only accounts the agent may read or pay from | Built |
| **Approved payees** | `payees` | Beneficiary ids the customer named at consent. Payees are fixed when the mandate is made: a beneficiary added later is not covered until the customer adds it to the mandate. (The PoC allows any existing beneficiary.) | Specified |
| **Cap per payment** | `limits.per_payment` | The largest single payment. It may not be more than the monthly limit | Specified |
| **Monthly limit** | `limits.per_month.amount` | The total per calendar month (South African time). Money held for unconfirmed payments counts against it | Built |
| **Monthly count** | `limits.per_month.count` | The most payments allowed per calendar month. Held payments count | Specified |
| **Grant length** | grant `expires` | Set by the customer within the bank's ceiling (`max_grant_days`, 90 days in the PoC) | Built |
| **Approval mode** | `approval` | `approved_payer`: every payment is approved in the bank app. `bill_payer`: payments within the limits proceed, and anything outside them is offered for approval | Specified (field). Built (bill payer behaviour) |

```json
{
  "type": "valet_payments",
  "actions": ["pay_existing_beneficiary"],
  "accounts": ["acc_123"],
  "payees": ["ben_water", "ben_city_power"],
  "approval": "bill_payer",
  "limits": {
    "per_payment": { "amount": "1000.00", "currency": "ZAR" },
    "per_month": { "amount": "2000.00", "currency": "ZAR", "count": 4 }
  }
}
```

The customer reads this as: *"Pay Water and City Power from Cheque ••4821, up to R1,000 a time, at most 4 payments and R2,000 a month, for 90 days. Anything else, ask me in the bank app."*

### When the customer must approve

A payment the mandate does not cover is not refused outright. The bank holds it as a payment intent and answers `403 approval_required` with the exact `valet_payment_once` the agent should request (Technical design §6). This applies to:

- **any payment, under `approved_payer`** (specified)
- **a new recipient**, or a beneficiary not on the mandate's `payees` (built for new recipients)
- **a payment over the monthly limit**: the approval may take the month over the limit, but only by that one amount (built)
- **a payment over the cap per payment, or past the monthly count** (specified)

**Approval rules (built):**
- An approval covers one exact action, matched by the digest of debtor account, payee, amount, currency and reference.
- It is bound to the payment intent the bank held, and it expires after 5 minutes.
- It is used up in the same locked step as the hold.
- It never adds a beneficiary or raises a limit.
- It counts towards the month's total and payment count.
- A second use, or a changed amount or payee, is refused with `approval_invalid`.

## 4. Check order on every call

The bank runs these checks in a fixed order and stops at the first failure (Technical design §5).

| # | Check | Failure |
| --- | --- | --- |
| 1 | DPoP proof is valid, fresh, unreplayed and matches the request | 401 `invalid_dpop_proof` |
| 2 | Token signature, audience, expiry | 401 `invalid_token` |
| 3 | The proof key is the key the grant was bound to at consent (`cnf.jkt`) | 401 `invalid_token` |
| 4 | Agent not denylisted, still trusted in the registry (for payments: registry reachable) | 403 `agent_denied`, `agent_untrusted`; 503 `registry_unavailable` |
| 5 | Grant is active and unexpired (live lookup) | 403 `grant_paused`, `grant_revoked`, `grant_expired` |
| 6 | The action is in `authorization_details` (type, action, account) | 403 `insufficient_authorization` |
| 7 | Payments: `Idempotency-Key` present. Payee on the mandate. Then, specified: within the cap per payment and the monthly count. Within the monthly limit, counting holds. The intent, the checks and the hold run in one locked step | 400 `invalid_request`; 422 `idempotency_key_reused`; 403 `approval_required` |
| 8 | Denylist checked again, then one idempotent instruction to the bank's payments API. Valet never executes a payment | 200 `paid`; 422 `payment_declined`, `insufficient_funds`, `payment_cancelled`; 202 `pending` |

## 5. Error codes

These are the codes an agent must handle. What each one means, and what the agent should do about it, is in Technical design §10.

| Group | Codes |
| --- | --- |
| Token and key | `invalid_token`, `invalid_dpop_proof` |
| Agent trust | `agent_denied`, `agent_untrusted`, `registry_unavailable` |
| Grant | `grant_paused`, `grant_revoked`, `grant_expired`, `insufficient_authorization` |
| Approval | `approval_required`, `approval_invalid` |
| Payment request | `invalid_request`, `idempotency_key_reused` |
| Payment outcome | `paid`, `pending` (202), `payment_declined`, `insufficient_funds`, `payment_cancelled` |
| Token and approval endpoints | `authorization_pending`, `slow_down`, `expired_token`, `access_denied`, `invalid_grant`, `invalid_authorization_details`, `unauthorized_client` |

**Specified:** the `approval_required` body gains a `reason` field, so an agent can tell the customer why a payment was stopped: `new_recipient`, `payee_not_on_mandate`, `over_per_payment`, `over_monthly_count`, `over_monthly_limit` or `approved_payer`.

## 6. Receipt format

Every decision writes a receipt: allowed, refused, declined by the bank, or with an unknown outcome. Receipts are signed with ES256 and hash-chained at the bank (Technical design §8). Each one names:
- the grant, the agent and the action
- the outcome and its basis (`grant`, `approval` or `refused`)
- the payment intent, the `Idempotency-Key` and the bank's payment id
- the mandate and its version
- the policy in force (`policy.version` and `policy.hash`)

**Specified:**
- The mandate's `intent` (a plain-language purpose) and the triggering instruction (supplied by the agent, labelled as such) appear on every receipt.
- There is one chain per grant.
- Personal data is kept outside the chain (POPIA).

## 7. Conformance

A deployment conforms to `valet-profile/0.7` when the conformance suite passes against it: `python -m pytest -q` and `python demo.py`. Each specified rule above gets its test when it is built. From then on, a deployment conforms only if that test passes as well.

**Profile items still to build:**
- the `approved_payer` level and the `approval` field
- named `payees`
- `per_payment` and `per_month.count`
- the `reason` on `approval_required`
- `intent` on mandates and receipts
