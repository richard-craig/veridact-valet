# The Valet insurance profile

**Version `valet-insurance-profile/0.1` (draft, 18 November 2026).** This applies the [Valet profile](valet-profile.md) to insurance: what an AI agent may do with a customer's policies, which changes always go back to the customer, and what the insurer can prove afterwards.

Banking asks *"who may move my money?"* Insurance asks *"who may change my cover?"* The mechanism is the same:
- a written mandate the customer reads before the agent starts;
- checks on every call, outside the model, in a fixed order, with a named reason when a request falls outside the mandate;
- a receipt the insurer keeps and nobody can rewrite.

Only the types and the reasons change. Everything else in the Valet profile applies unchanged: agent keys bound with DPoP, the check order up to the mandate check (§4 there, steps 1 to 6), approvals bound to one action and used once, receipts with personal data outside the chain, and the conformance rules.

Status: **Proposed.** Nothing in this document is built yet. §8 lists what building it takes.

## 1. Why insurance needs its own types

In banking, the harm is money leaving, and money can be capped. In insurance, the harm is usually **cover quietly changing**. A cancelled policy, a reduced sum insured, a changed beneficiary, or a replacement that resets waiting periods may not show until the day a claim is refused. Amount limits don't catch that, so the profile names the changes that always go back to the customer, whatever the mandate says (§4).

Insurance also handles more sensitive data than banking. Life, disability and medical claims carry health information, which POPIA treats as special personal information. The profile keeps that data out of the agent's reach unless the customer has consented to it specifically, and always keeps it out of the receipt chain (§6).

## 2. Permission types

These are carried as RFC 9396 `authorization_details`, like the payment types. Premium payments reuse `valet_payments` from the payment profile, with the insurer as the named payee.

| Type | What it carries |
| --- | --- |
| `valet_policies` | Read access. `actions`: `read_policy` (schedule, cover, premium), `read_documents`, `read_claims`. `policies`: the policy ids the customer chose. `special_information`: `false` by default (see §6) |
| `valet_claims` | Claims on the customer's behalf. `actions`: `submit_claim`, `upload_evidence`, `read_claim_status`. `policies`, `claim_types` (for example `motor_accident`, `theft`, `glass`, `geyser`, `travel_delay`), and `limits`: `per_claim` (the claimed amount the customer estimates), `per_year.count` |
| `valet_policy_changes` | Low-risk changes. `actions` drawn from `update_contact_details`, `add_named_driver`, `add_specified_item`, `change_vehicle`, `change_premium_date`. `policies`, `limits.premium_increase` (the most the premium may rise in total per year because of agent changes), `approval` |
| `valet_policy_change_once` | Exactly one change from the protected list (§4), offered by the insurer and approved by the customer, like `valet_payment_once`. The agent never constructs one |
| `valet_payments` | Premium payments. Defined in the payment profile |

Every detail carries an `intent`, a plain-language purpose such as "Handle the claim for my cracked windscreen". It is shown at consent and recorded on every receipt.

**Example: a Claims assistant mandate**

```json
[
  {"type": "valet_policies", "actions": ["read_policy", "read_claims"],
   "policies": ["pol_motor_7781"], "special_information": false},
  {"type": "valet_claims", "actions": ["submit_claim", "upload_evidence", "read_claim_status"],
   "policies": ["pol_motor_7781"], "claim_types": ["motor_accident", "glass", "theft"],
   "limits": {"per_claim": {"amount": "25000.00", "currency": "ZAR"}, "per_year": {"count": 2}},
   "intent": "Lodge and follow up claims on my car policy"}
]
```

The customer confirms: *"Claims assistant: lodge and follow up motor accident, glass and theft claims on Motor policy ••7781, up to R25,000 a claim and 2 claims a year, and view the policy and its claims, for 90 days. Accepting or disputing a settlement always comes back to you."*

## 3. Access levels

| Level | Types | The agent may | The agent may never |
| --- | --- | --- | --- |
| **Policy viewer** | `valet_policies` | See the chosen policies, their documents and claim status | Change anything, submit claims, see health information |
| **Claims assistant** | `valet_policies` + `valet_claims` | Lodge claims of the chosen types and amounts, upload evidence, follow them up | Accept or dispute a settlement, withdraw a claim, change cover |
| **Policy admin** | `valet_policies` + `valet_policy_changes` | Make the chosen low-risk changes within the premium limit | Reduce cover, cancel, change a beneficiary or payout details, replace a policy |
| **Premium payer** | `valet_payments` | Pay premiums to the insurer within the payment profile's limits | Pay anyone else |

A level asks for the customer's approval in the insurer's app either every time (`every_action`, the pilot default) or only for requests outside the mandate (`within_limits`). That's the same choice as Approved payer and Bill payer in the payment profile.

**No advice.** At every level, the agent carries out the customer's instructions. It doesn't recommend products, cover or sums insured. The consent screen says so. Whether an agent that does recommend needs a financial-services licence is a question for compliance (§7).

## 4. Protected actions

These are never covered by a standing mandate, whatever its level or limits. Each one is offered to the customer as a `valet_policy_change_once` and needs **fresh authentication** in the insurer's app. The approval screen states the consequence in the insurer's own words, never in the agent's.

| Protected action | Reason | What the approval screen must show |
| --- | --- | --- |
| Reduce cover or sum insured, add an excess | `cover_reduction` | Old and new cover, and what would no longer be paid |
| Cancel a policy | `cancellation` | The cancellation date, any refund, and what is uninsured from then on |
| Replace a policy with another | `replacement` | Waiting periods, exclusions or loadings that restart, and what is lost from the old policy |
| Change a beneficiary or cessionary | `beneficiary_change` | Old and new, in full |
| Change the bank account for premiums or payouts | `payout_details_change` | Old and new account. This is the classic fraud route |
| Accept, dispute or withdraw a claim or settlement | `settlement_decision` | The offer, and what accepting it waives |

The insurer **may** add a cooling-off delay before a protected action takes effect, and should for cancellations and replacements. A `settlement_decision` is never covered by any threshold, even for small amounts.

## 5. The mandate check

One check, used by every front door (direct API and MCP gateway), applies these rules in order. The first rule a request breaks is the reason. This extends the payment profile's §3.

| Order | Reason | The request... |
| --- | --- | --- |
| 1 | `policy_not_on_mandate` | is for a policy the customer didn't choose |
| 2 | `action_not_on_mandate` | is a claim type or change type the customer didn't choose |
| 3 | `cover_reduction`, `cancellation`, `replacement`, `beneficiary_change`, `payout_details_change`, `settlement_decision` | is a protected action (§4) |
| 4 | `over_claim_value` | claims more than `per_claim` |
| 5 | `over_claim_count` | would exceed the year's claim count. Claims under assessment count |
| 6 | `over_premium_increase` | would raise the premium past `premium_increase` for the year, counting earlier agent changes |
| 7 | `every_action` | is under a mandate that approves every action |

Reasons 1, 2 and 4 to 6 are offered for approval on the direct API, the same way as payments. On the MCP gateway they are refusals. Reason 3 is always offered as a single-use approval with fresh authentication, on every front door, and is never refused silently: the customer should know their agent tried.

**Claims aren't payments.** A claim's amount is the customer's estimate, not money leaving. `per_claim` exists so that a large claim, which is likelier to be investigated and costlier if wrong, goes past the customer before it is lodged in their name. Lodging is still the customer's act, so the agent may never submit a claim the customer hasn't seen when the claim is over the limit.

## 6. Receipts and sensitive data

Receipts follow the payment profile's §6: hash-chained, signed by the insurer, with a reason code, an approval id and the policy in force. Insurance adds:

| Field | Meaning |
| --- | --- |
| `policy_id`, `claim_id` | What the action was about |
| `change` | For a policy change: the field, `from` and `to`, kept as personal data outside the chain |
| `evidence` | For each document the agent uploaded: its SHA-256 digest, media type and size. The document itself is never in the chain. Months later, the insurer can show exactly which photo or quote was submitted, and that it hasn't changed since |
| `fresh_auth` | For protected actions: when and how the customer re-authenticated |

**Special personal information.** Health data in life, disability, funeral and medical claims never enters the chain. Not as text, and not as a field name that reveals a condition. The agent can read it only if `special_information: true` appears in a `valet_policies` or `valet_claims` mandate that the customer consented to separately, on its own screen, with its own wording. Without that flag, the insurer's API returns policy and claim data with special information removed.

**Disputes.** A complaint to the insurer, or later to the ombud, can be settled from one record. Together, the receipts show what the customer authorised, what the agent asked for and in its own words, which rule applied, what the customer approved and when, and which evidence was lodged.

## 7. Regulatory questions to settle before a pilot

These shape the design but aren't settled. Each needs an answer from the insurer's compliance team or counsel.

- **Advice:** does an agent that only carries out instructions fall outside the definition of financial advice (FAIS), and what wording on the consent screen keeps it there?
- **Policyholder protection rules:** do the insurer's rules on cancellations, replacements and communications to policyholders apply to agent-initiated requests, and does a single-use approval with fresh authentication meet them?
- **POPIA special personal information:** is the separate `special_information` consent enough as the legal basis for an agent to process health data, or does the insurer need more?
- **Claims fraud and misrepresentation:** if an agent lodges a claim with wrong facts, who bears it? The `agent_supplied_instruction` and `evidence` fields record what happened. The allocation of responsibility belongs in the agent operator's terms.
- **Binder and intermediary arrangements:** where policies are sold through brokers or underwriting managers, which party runs Valet and holds the receipts?

## 8. Building it

The bank-side machinery already exists: grants, key binding, the mandate check, approvals, the receipt chain, and the MCP gateway. Building insurance means:

1. **Types and levels:** the four insurance types and levels in `levels.py`, and a consent screen for each, including the separate special-information screen.
2. **Mandate check:** an insurance branch of `mandate.py` with the reasons in §5, in order, and the protected-action list in §4.
3. **Single-use approvals:** `valet_policy_change_once` and `settlement_decision` approvals with fresh authentication (a step-up `acr` on the approval request).
4. **Receipts:** `policy_id`, `claim_id`, `change` outside the chain, and evidence digests.
5. **Adapters:** a policy-administration and claims adapter, in the same role as the payments adapter. Valet decides, holds and records, and the insurer's own systems carry the action out.
6. **Conformance tests:** one per reason, and one per protected action proving it can never pass on a standing mandate.
7. **Demo:** an insurer alongside Marula Bank, with Kaya lodging a windscreen claim within the mandate and then attempting a cancellation that comes back to the customer.

**Standards.** Once built and piloted, the insurance types could become a second short Internet-Draft in the same shape as `draft-craig-oauth-rar-payment-mandates`, or a section of its -01 that generalises the mandate check beyond payments. The second is probably better, since one draft with two domains shows the pattern is general.
