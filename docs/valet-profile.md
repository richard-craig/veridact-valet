# The Valet profile

**Version `valet-profile/0.8` (17 November 2026).** This is the shared permission standard every Valet deployment implements: the access levels, the approval rules, the check order on every call, the error codes and the receipt format. With it, one agent integration works at every organisation that runs Valet.

The profile is what the Valet project defines. Each bank decides which levels, accounts, limits and grant lengths it offers, within the profile (Technical design §1.2). The code reports the profile version it implements in every policy document (`valet/bank/policy.py`, `PROFILE_VERSION`), so every receipt names the rules it was checked against.

Status marks:
- **Built**: in the proof of concept and covered by a conformance test (`tests/test_profile.py`).
- **Specified**: part of the profile, not yet built.

## 1. Permission types

Permissions travel as OAuth Rich Authorization Requests (RFC 9396, `authorization_details`), so the mandate the customer approves and the grant the bank enforces are one record.

| Type | What it carries | Status |
| --- | --- | --- |
| `valet_accounts` | Read access: `actions` (`read_balances`, `read_transactions`), `accounts`, `history_days`, `intent` | Built |
| `valet_payments` | A standing payment mandate: `actions` (`pay_existing_beneficiary`), `accounts`, `payees`, `approval`, `limits` (`per_payment`, `per_month.amount`, `per_month.count`, optional `approve_above`), `intent` | Built |
| `valet_payment_once` | Exactly one payment: `from`, `to` (name and account), `amount`, `reference`. The bank offers it when a payment needs approval; the agent never invents one | Built |

In AP2 terms, `valet_payments` is an open mandate and `valet_payment_once` is a closed one.

**`intent`** is a plain-language purpose of up to 140 characters, such as "Pay my monthly utility bills". The agent may propose it when it connects. The customer sees it on the consent screen and can change it there. It is stored on every detail of the grant and recorded on every receipt for the grant (§6).

## 2. Access levels

Levels are named templates over the types. The agent may ask for a level. The customer chooses on the consent screen, and the grant records what the customer chose, never what the agent asked for (`valet/bank/levels.py`).

| Level | Code | Types | The agent may | The agent may never | Status |
| --- | --- | --- | --- | --- | --- |
| **View only** | `view_only` | `valet_accounts` | See balances and 90 days of transactions on the chosen account | Move money, add beneficiaries, change limits, see card numbers or passwords | Built |
| **Approved payer** | `approved_payer` | `valet_accounts` + `valet_payments` | Prepare payments to the mandate's payees. **The customer approves every payment in the bank app.** Pilot default for anything that moves money | Pay without the customer's approval, add beneficiaries, change limits | Built |
| **Bill payer** | `bill_payer` | `valet_accounts` + `valet_payments` | Pay the mandate's payees within the limits without asking each time | Pay anyone outside the mandate without asking, add beneficiaries, change limits | Built |

**Risk hints.** Each level and action carries the Personal Agent Protocol's scope hints (Poppy 1.1 §4.7): `changes`
says whether it changes anything, and whether that can be undone (`none`, `reversible`, `irreversible`; anything
unknown counts as `irreversible`), and `personal_data` says whether it reveals personal data. The bank publishes them
in `/.well-known/poppy.json` ([Poppy extension](poppy-extension.md) §2), and consent screens can use them to say
plainly what a level allows (`valet/bank/poppy.py`, built).

| Level or action | `changes` | `personal_data` |
| --- | --- | --- |
| `view_only`, `read_balances`, `read_transactions` | `none` | `true` |
| `approved_payer`, `bill_payer`, `pay_existing_beneficiary` | `irreversible` | `true` |

## 3. Approval rules

These are the named constraints on a `valet_payments` mandate. The customer sets each one on the consent screen. Each one is stored in the mandate, written into the consent wording (whose hash is kept as consent evidence), and applied on every call.

| Constraint | Field | Rule | Status |
| --- | --- | --- | --- |
| **Accounts** | `accounts` | The only accounts the agent may read or pay from | Built |
| **Approved payees** | `payees` | Beneficiary ids the customer ticked at consent, at least one. If the customer doesn't choose, the payees are the beneficiaries saved at consent. A beneficiary saved later is not covered until the customer adds it to the mandate | Built |
| **Cap per payment** | `limits.per_payment` | The largest single payment. Never more than the monthly limit. Defaults to the monthly limit | Built |
| **Monthly limit** | `limits.per_month.amount` | The total per calendar month (South African time). Money held for unconfirmed payments counts against it. The bank sets a ceiling (`max_monthly_limit`) | Built |
| **Monthly count** | `limits.per_month.count` | The most payments per calendar month. Held payments count, and so do payments approved by the customer. The bank sets a ceiling (`max_monthly_count`, 20 in the PoC) and a default (`default_monthly_count`, 10) | Built |
| **Approval threshold** | `limits.approve_above` | Bill payer only, optional: payments above this amount are offered to the customer for approval | Built |
| **Approval mode** | `approval` | `approved_payer`: every payment is approved in the bank app. `bill_payer`: payments inside the mandate proceed, and anything else is offered for approval | Built |
| **Grant length** | grant `expires` | Within the bank's ceiling (`max_grant_days`, 90 days in the PoC) | Built |

```json
{
  "type": "valet_payments",
  "actions": ["pay_existing_beneficiary"],
  "accounts": ["acc_4821"],
  "payees": ["ben_water", "ben_city_power"],
  "approval": "bill_payer",
  "limits": {
    "per_payment": { "amount": "1000.00", "currency": "ZAR" },
    "per_month": { "amount": "2000.00", "currency": "ZAR", "count": 4 },
    "approve_above": { "amount": "500.00", "currency": "ZAR" }
  },
  "intent": "Pay my monthly utility bills"
}
```

The customer confirms: *"Bill payer: pay Water & Sanitation, City Power from Cheque account ••4821, up to R1,000.00 a payment, at most 4 payments and R2,000.00 a month, and view balances and transactions, for 90 days. You approve any payment over R500.00, and anything outside these limits, in the bank app. Purpose: Pay my monthly utility bills."*

### Reasons a payment needs the customer

One function, `valet/bank/mandate.py`, checks every payment against the mandate, in this order. Both front doors use it: the direct API and the MCP gateway. The first rule the payment breaks becomes the **reason**.

| Order | Reason | When | MCP gateway code |
| --- | --- | --- | --- |
| 1 | `new_recipient` | The payee is not a saved beneficiary | `PAYEE_NOT_IN_MANDATE` |
| 2 | `payee_not_on_mandate` | Saved, but not one of the mandate's payees | `PAYEE_NOT_IN_MANDATE` |
| 3 | `over_per_payment` | Above the cap per payment | `PER_PAYMENT_CAP_EXCEEDED` |
| 4 | `over_monthly_count` | The month already has the most payments allowed | `MONTHLY_COUNT_REACHED` |
| 5 | `over_monthly_limit` | The month's total, counting holds, would go over the limit | `MONTHLY_LIMIT_EXCEEDED` |
| 6 | `approved_payer` | The mandate's approval mode is Approved payer | (every gateway payment is approved) |
| 7 | `over_approval_threshold` | Above `approve_above` | (every gateway payment is approved) |

**On the direct API**, a payment with a reason is held as a payment intent. The bank answers `403 approval_required` with the exact `valet_payment_once` to request, the `payment_intent_id` and the `reason` (Technical design §6).

**On the MCP gateway**, reasons 1 to 5 are refusals (`DECLINED` with the code). Every gateway payment is already approved by the customer, and an approval there never widens the mandate. The gateway also counts payments still waiting for the customer against the count and the limit. A payment inside the mandate is `APPROVAL_REQUIRED`, with the reason recorded as `bearer_tier` or reason 6 or 7.

**Approval rules:**
- An approval covers one exact action, matched by the digest of debtor account, payee, amount, currency and reference.
- It is bound to the payment intent the bank held, and it expires after 5 minutes.
- It is used up in the same locked step as the hold.
- It never adds a beneficiary or a payee, and it never raises a limit.
- It counts towards the month's total and payment count.
- A second use, or a changed amount or payee, is refused with `approval_invalid`.

## 4. Check order on every call

The bank runs these checks in a fixed order and stops at the first failure (Technical design §5).

| # | Check | Failure |
| --- | --- | --- |
| 1 | The DPoP proof is valid, fresh, not replayed, and matches the request | 401 `invalid_dpop_proof` |
| 2 | Token signature, audience and expiry are valid | 401 `invalid_token` |
| 3 | The proof key is the key the grant was bound to at consent (`cnf.jkt`) | 401 `invalid_token` |
| 4 | The agent is not denylisted and is still trusted in the registry. For payments, the registry must be reachable | 403 `agent_denied`, `agent_untrusted`; 503 `registry_unavailable` |
| 5 | The grant is active and unexpired (a live lookup) | 403 `grant_paused`, `grant_revoked`, `grant_expired` |
| 6 | The action is in `authorization_details` (type, action, account) | 403 `insufficient_authorization` |
| 7 | Payments: an `Idempotency-Key` is present, then the mandate check (§3, reasons 1 to 7). The intent, the check and the hold run in one locked step | 400 `invalid_request`; 422 `idempotency_key_reused`; 403 `approval_required` with `reason` |
| 8 | Denylist checked again, then one idempotent instruction to the bank's payments API. Valet never executes a payment | 200 `paid`; 422 `payment_declined`, `insufficient_funds`, `payment_cancelled`; 202 `pending` |

## 5. Error codes

These are the codes an agent must handle. What each one means, and what the agent should do about it, is in Technical design §10.

| Group | Codes |
| --- | --- |
| Token and key | `invalid_token`, `invalid_dpop_proof` |
| Agent trust | `agent_denied`, `agent_untrusted`, `registry_unavailable` |
| Grant | `grant_paused`, `grant_revoked`, `grant_expired`, `insufficient_authorization` |
| Approval | `approval_required` (with `reason`, §3), `approval_invalid` |
| Payment request | `invalid_request`, `idempotency_key_reused` |
| Payment outcome | `paid`, `pending` (202), `payment_declined`, `insufficient_funds`, `payment_cancelled` |
| Token and approval endpoints | `authorization_pending`, `slow_down`, `expired_token`, `access_denied`, `invalid_grant`, `invalid_authorization_details`, `unauthorized_client` |

## 6. Receipt format

Every decision writes a receipt: allowed, refused, held for approval, declined by the bank, cancelled, unknown or escalated. Each receipt is a JSON record, hashed (SHA-256 over the JCS-canonical record, including the previous receipt's hash), chained, and signed by the bank's receipt key (ES256 over `{seq, hash}`).

```json
{"seq": 42, "prev": "sha256:9c1e…", "time": "2026-11-17T10:42:07+02:00",
 "grant_id": "g_3fa8…", "agent": "kaya", "customer": "cus_thandi", "grant_level": "bill_payer",
 "action": "payment", "outcome": "allowed", "basis": "approval",
 "reason_code": "new_recipient", "approval": "ar_51b0…",
 "detail": {"to": "City Power", "account": "30087712", "amount": "300.00", "currency": "ZAR", "reference": "Oct"},
 "payment_intent": "pi_8Qm2…", "idempotency_key": "city-power-oct-2026", "bank_payment_id": "bp_Jx41…",
 "channel": "api", "intent_evidence": "customer_confirmed",
 "mandate": {"id": "g_3fa8…", "version": 1},
 "policy": {"version": "CHG-2026-1182", "hash": "sha256:4be0…"},
 "personal": {"intent": "sha256:…", "agent_supplied_instruction": "sha256:…"}}
```

| Field | Meaning | Status |
| --- | --- | --- |
| `seq`, `prev`, `time` | Position in the chain, the previous receipt's hash, and the time (South African time) | Built |
| `grant_id`, `agent`, `customer`, `grant_level` | Whose mandate, which agent, which customer (bank id), and which level | Built |
| `action`, `outcome`, `basis` | What was asked for; `allowed`, `refused`, `held`, `failed`, `cancelled`, `unknown` or `escalated`; and why it was allowed: `grant` (standing mandate), `approval` (the customer approved) or `refused` | Built |
| `reason_code` | The mandate rule the payment fell outside (§3), on the held receipt and on the receipts that settle it | Built |
| `approval` | The id of the customer's approval that allowed it | Built |
| `payment_intent`, `idempotency_key`, `bank_payment_id`, `channel` | Match Valet's record against the bank's payment record, line for line | Built |
| `mandate` | The mandate and its version | Built |
| `policy` | The bank's policy reference and the hash of the policy document in force | Built |
| `personal.intent` | Salted hash of the mandate's purpose | Built |
| `personal.agent_supplied_instruction` | Salted hash of what the agent says it was asked to do, labelled as the agent's words. Never trusted, never used to decide | Built |
| `detail` | Payee name, account, amount and reference | Built (still inside the chain) |

**Personal data outside the chain (POPIA).** Free text that can identify a person or describe their affairs is never written into the chained record. That covers the purpose and the agent's instruction. The record holds a salted hash. The value and its salt are kept in a separate table, `receipt_personal`, that the bank can erase for a grant (`erase_personal`) without breaking the chain. A dispute can check a disclosed value against the chained hash with its salt (`personal(seq)`). Evidence packs (Technical design §8.3) carry the hashes, not the values.

**Specified, not yet built:**
- Move `detail` (payee names and account numbers) into the same erasable store, leaving pseudonymous ids in the chain.
- One chain per grant, with chain heads published.
- Signed receipts returned to the agent in each response.
- A receipt-key id (`kid`) on each receipt.

## 7. Conformance

A deployment conforms to `valet-profile/0.8` when the conformance suite passes against it:
- `tests/test_profile.py`: every reason in §3 on the direct API, rule order, approvals counting towards the month, consent validation, the same rules on the MCP gateway, and the receipt format, including erasure without breaking the chain;
- the rest of `python -m pytest -q`;
- `python demo.py`.

A test in the suite fails if a reason is added to `mandate.REASONS` without its own conformance test.

## 8. Standards

**Valet is aligned with emerging OAuth agent work, not built on it, and its profile fills gaps that work leaves open.** The OAuth working group has many individual drafts on AI agents. As far as we can find, none has been adopted, and none defines banking constraints or signed per-action evidence. Valet's design review (9 November 2026) found exactly those two gaps.

| Draft | What it covers | How Valet relates |
| --- | --- | --- |
| `draft-rosomakho-oauth-txn-challenge-00` (June 2026; Zscaler, Ping Identity, Defakto) | A resource server challenges for approval of one specific transaction with a signed challenge (`authorization_details`, `reason`); the client relays it to the authorisation server, the approver decides, and a short-lived token for that transaction comes back | The same shape as Valet's `approval_required` → CIBA → single-use `valet_payment_once` token. Valet adds machine-readable reason codes and a signed receipt of the approval. The draft has neither; its `reason` is human-readable text |
| `draft-chen-oauth-agent-authz-use-cases` (revisions to -05, October 2026) | A gap analysis; names "execution layer evidence" as a gap | Valet's receipt format (§6) is a concrete answer |
| `draft-chen-oauth-rar-agent-extensions-01` | Policy, lifecycle and intent extensions to RAR | Expired 24 October 2026. Valet's `intent` and named constraints cover the same ground for payments |
| `draft-hulea-wimse-agent-mandate-00` (WIMSE, October 2026) | Verifiable mandates across administrative domains, reusing RAR and token exchange | Complementary: cross-domain mandate transport. Valet is the enforcement and evidence at the bank |

**Recommended route.** Submit the banking constraints and the receipt format as one short individual draft: *"Rich Authorization Requests profile for agent payment mandates"* (working name `draft-craig-oauth-rar-payment-mandates-00`). It would define:
1. the `valet_payments` and `valet_payment_once` detail types and their named constraints (§1, §3);
2. the reason codes, and how they are carried in an `approval_required` response, aligned with the transaction-challenge draft's `reason`, so the two compose;
3. the receipt record and its personal-data split (§6);
4. security and privacy considerations, including POPIA and GDPR erasure.

Present it at an OAuth working group interim or IETF meeting alongside the transaction-challenge authors, with Valet as the running code, and ask for adoption rather than starting a new effort. Before submitting: settle the type names (drop the `valet_` prefix in favour of neutral names), get legal advice on the IETF IPR declaration, and line up at least one bank or vendor co-author. Until then, in pitches, say *"aligned with emerging OAuth agent standards"*, not "built on" them.
