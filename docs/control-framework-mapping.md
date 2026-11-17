# Veridact Valet: Control framework mapping

Version 0.1 · 17 November 2026 · For bank CISOs, risk, compliance and audit teams

**Bank control frameworks for AI agents now put the security boundary at the agent's authority to act, not only at the data it reads. For agents acting on a customer's money, Valet is that boundary: authority written down before the agent acts, checked outside the model on every call, and recorded in evidence the agent cannot rewrite.** This document maps Valet against such a framework, so a bank can see which controls Valet provides, which it leaves to the bank, and how far each is proven.

The reference framework is Mervin Pearce, [*Securing AI Agents in Banking*](https://mervinpearce.com/securing-ai-agents-in-banking/) (17 November 2026). It proposes autonomy tiers, assurance states, a minimum evidence set, a list of what stopping an agent must cover, and board questions. Its tier model and assurance states are the author's proposals, not a published standard; we use them because they are concrete enough to test against. Its examples are built on one vendor's stack; nothing below depends on any vendor.

**Scope.** The framework is written mainly for a bank's own agents (fraud operations, staff assistants). Valet is for agents acting **for customers**: third-party assistants and apps, and the bank's own customer-facing agents. The two meet wherever an agent can move a customer's money, which is the boundary Valet sets. Everything else in the framework (staff agents, data loss prevention, model risk for the bank's own models) stays with the bank's existing controls.

## 1. Autonomy tiers

The framework grades agents by what they can do: **R1 informational**, **R2 advisory**, **R3 transactional**, **R4 critical**, with more governance at each step. Valet grades the same thing on two axes: **what the mandate allows** (the access level, set by the customer within the bank's policy) and **how strongly the agent proves itself** (the assurance tier, which caps the access level). Neither axis is left to the agent.

| Tier | What it means | Valet access level | Lowest assurance tier allowed | What enforces it |
| --- | --- | --- | --- | --- |
| **R1** Informational | Reads and reports | **View only**: balances and 90 days of transactions on the accounts the customer picked | Bearer, platform client (Claude, ChatGPT today) | The grant is checked on every call; no money-moving action exists in the mandate |
| **R2** Advisory | Recommends; a person acts | **View only**. The customer acts on the advice in the bank's own app | Bearer, platform client | Advice carries no authority. To act, an agent needs a mandate of its own; a recommendation never borrows one |
| **R3** Transactional | Acts within set limits | **Bill payer**: pay existing beneficiaries up to a monthly limit, as a standing mandate | DPoP-bound (lower caps), or DPoP-bound and Veridact-verified (the bank's full caps). Never the bearer tier | Per-call checks outside the model, the monthly ledger, payment intents, receipts marked `standing_mandate` |
| **R4** Critical | High impact or hard to undo | **Approved payer**: the customer approves each payment in the bank app (CIBA). At every level, a payment to someone who is not a saved beneficiary also needs the customer's approval | Any tier, because the approval comes from the customer's own channel, not the agent | Single-use approval bound to one payment intent; receipts marked `customer_confirmed` |
| Above R4 | Changes the controls themselves | **Never delegated**: adding beneficiaries, changing limits, seeing credentials, card numbers or passwords | Not available to any agent | Not in the profile; no endpoint exists |

**Advisory agents feeding automated actions.** The framework warns that an "advisory" agent whose output feeds an automated action carries the consequences of the action. In Valet that hand-off cannot happen silently: whatever performs the action must hold its own mandate, bound to its own key, and is checked as R3 or R4 when it acts. A view-only agent that persuades another agent to pay is still stopped at the second agent's mandate. Agent-to-agent delegation is out of scope today ([Threat model](threat-model.md)); when it arrives, a delegated agent will get at most the narrower of the two mandates, never the union.

**Recording the tier.** Each receipt carries `grant_level`, `basis` (`grant`, `approval`, `refused`) and `intent_evidence`, from which the R tier of every decision follows mechanically. We do not stamp R labels into the receipt format, because the tier model is a proposal; a bank's monitoring can map the fields to its own tiers.

## 2. Assurance states: declared, configured, tested, proven effective

The framework asks that every control be graded **declared** (documented), **configured** (in place), **tested** (shown to work), or **proven effective** (shown to work in the deployment, over time), and that unknown evidence stay unknown rather than be scored as compliant. Valet's own statuses map onto these: *Designed* is declared; *Built* is configured in the proof of concept; *Built and tested* is tested **in the proof of concept**. **Nothing below is proven effective yet.** Only a bank can reach that state, in its own deployment, with its own database, payments adapter, identity platform and adversarial testing.

| Control | State | Evidence | What moves it up |
| --- | --- | --- | --- |
| Authority checked outside the model on every call | Tested (PoC) | `tests/test_valet.py`, `demo.py` (24 checks) | Pilot on the bank's API and identity platform |
| Grant bound to the agent's key (DPoP) at consent | Tested (PoC) | `test_valet.py::test_stolen_token…`, `test_handoff.py` | FAPI 2.0 conformance run (Technical design §14.1) |
| Customer approval for each payment (Approved payer) | Tested (PoC) | `test_payments.py`, `test_mcp.py` | Push approvals in a test build of the bank's app |
| A payment is made at most once, across retries, crashes and timeouts | Tested on SQLite only | `test_payments.py`, `test_stopping.py` | **Postgres with concurrency and failure injection, a POC deliverable** (Technical design §17) |
| Emergency stop: refuses, sweeps, records | Tested (PoC) | `test_evidence.py`, `test_stopping.py` | Multi-node test against the bank's database |
| Signed, hash-chained receipts naming mandate and policy version | Tested (PoC) | `test_evidence.py`, `test_valet.py` | Receipt key in the bank's HSM; retention set by the bank |
| Evidence packs, verifiable offline | Tested (PoC) | `test_evidence.py` | Used in a real dispute or incident exercise |
| Per-grant receipt chains with published heads | Declared | Technical design §8 | Build |
| Authentication context recorded on approvals | Declared | Technical design §8.1 | Build |
| Resistance to prompt injection | Tested for one scenario | A planted transaction narrative tells the assistant to pay a loan company; even if the model obeys, the bank declines it (`test_mcp.py`, `scripts/preflight.py` against Keycloak) | Adversarial testing by the bank's red team: tool misuse, payee lookalikes, approval fatigue |
| A misled agent acting **inside** its standing limit | **Not controlled**, by design | Technical design §11 | Approved payer for that class of payment |

## 3. The minimum evidence set

The framework names what a bank must be able to show for an agent action, using a blocked account restriction as its example: the attempted request, the agent identity, the policy version, the authorisation outcome, the blocked action, the timestamp, and the resulting event. Every Valet receipt carries each of these, inside one signed, chained record.

| Evidence asked for | Receipt field | Status |
| --- | --- | --- |
| Attempted request | `action` (the endpoint or tool), `detail` (payee, amount, reference), `payment_intent`, `idempotency_key` | Built |
| Agent identity | `agent` (the client), the grant's bound key (`jkt`) and token issuer, the operator from the registry | Built |
| What the customer allowed | `mandate`: id and version | Built |
| **Policy version** | `policy`: the bank's change reference and the hash of the full policy document, kept and checkable (Technical design §8.2) | **Built in 0.7** |
| Authorisation outcome | `outcome`, `basis`, and the reason code for any refusal | Built |
| Blocked action | `outcome: refused` with `reason` (for example `denylisted`, `limit_exceeded`, `registry_unavailable`) | Built |
| Timestamp | `time` (South African time), and `seq` in the chain | Built |
| Resulting event | The bank's `bank_payment_id`, or the cancellation, escalation or stop counts | Built |
| Beyond the set: evidence of the customer's intent | `intent_evidence` and the `approval` id (Technical design §8.1) | Built |
| Beyond the set: the instruction the agent says it acted on | `triggering_instruction`, labelled as the agent's words | Designed |

A dispute or incident team exports all of this, with the policy documents and signatures, as an evidence pack (Technical design §8.3).

## 4. Stopping an agent, and cleaning up

The framework lists six things a bank must be able to do when an agent goes wrong. All six are covered; the right-hand column says who owns each.

| Requirement | Valet | Owner |
| --- | --- | --- |
| **Suspension** | The customer pauses one agent or all agents in the bank app; the bank denylists a client, an operator or a key. Both take effect on the next request (Technical design §7, §9.1) | Valet, built |
| **Credential revocation** | Revoke deletes refresh tokens; the denylist can stop a single key; withdrawing registry trust stops an agent within 60 seconds. Agent key rotation and compromise response with Veridact are open (Technical design §16) | Valet built; key rotation open |
| **Safe handling of partial actions** | Every payment is a durable intent. The bank's acceptance is the point of no return: before it, stopping cancels; after it, the payment completes and the customer is told. A payment that may be with the bank is settled by cancel-or-confirm, never released on a timer (Technical design §5.1) | Valet, built |
| **Fallback processes** | Valet is never the only way to pay: the customer can still pay in the bank's app or branch. A cancelled payment returns `payment_cancelled` and the activity page says what happened. Recovery time and recovery point objectives, and how long revocation may take to propagate, are the bank's to set | Bank, with Valet's signals |
| **Evidence preservation** | Receipts are append-only, signed and chained; the emergency stop is recorded in the same chain; evidence packs export and preserve the record for one grant or one agent (Technical design §8, §8.3) | Valet built; HSM keys, retention and legal hold are the bank's |
| **Reconciliation** | Unsettled payments are reconciled against the bank's payment system on a schedule; anything the bank cannot answer goes to the `payments-unknown-outcome` queue, still held against the limit (Technical design §5.1) | Valet built; the queue's service level is the bank's |

## 5. The board's questions

| The board asks | The answer Valet lets a bank give |
| --- | --- |
| Which agents can act on our customers' accounts? | Every one holds a grant at the bank, listed per customer (the AI agents screen) and per agent; agents are admitted only through the bank's registry |
| Who owns each one? | The operator, from the registry (Veridact in production), never from the agent's own request; the accountable person on the bank's side owns the policy, named by its change reference on every receipt |
| Can an agent do something the customer did not allow? | Not past the mandate: payees, amounts and frequency are checked by the bank on every call. Inside a standing limit, a misled agent can act; that is why Approved payer exists, and the record says which kind of evidence each payment has |
| Would we know if an agent were being manipulated? | Valet does not try to detect prompt injection inside the model. It makes manipulation stop at the mandate, and records every refused attempt, which the bank's monitoring can alert on |
| Can we stop agents quickly? | Yes: the customer in one tap, the bank for one agent, one operator or one key, on the next request, with in-flight payments cancelled or confirmed and the stop recorded |
| Can we show the controls work? | Each guarantee is mapped to a test (Technical design §17); the bank re-runs them against its own deployment and keeps the results. Signed evidence packs show individual decisions to a third party |

## 6. Regulation

**This section is orientation for counsel, not legal advice.** It names the instruments a South African bank is likely to test Valet against, and what in Valet bears on each. Where we are unsure, we say so.

### South Africa

| Instrument | What it asks, in short | What in Valet bears on it | Open |
| --- | --- | --- | --- |
| **National Payment System Act, SARB Directive 2 of 2024** (EFT credit payment instructions issued on behalf of the payer; effective 15 February 2025) | A person issuing EFT payment instructions on a payer's behalf must register with the SARB, show it secures the payer's data and banking credentials, and get the payer's informed consent first | Valet removes the credential sharing the Directive targets: the agent gets a bank-issued key and never sees a password, PIN or OTP. The consent screen and its hash are evidence of informed consent, before the agent acts | **Counsel's view needed:** whether agent operators that ask the bank to pay through Valet are "issuing" instructions within the Directive and must register (threat model G10) |
| **Joint Standard 1 of 2023**, IT governance and risk management (FSCA and Prudential Authority; commenced 15 November 2024) | The governing body is accountable; an IT risk management framework, IT strategy, change and service management | Open code, design, threat model and tests the bank can audit as part of its IT risk management. The policy reference on every receipt ties each decision to the bank's own change record | The bank's risk acceptance for each access level |
| **Joint Standard 2 of 2024**, cybersecurity and cyber resilience (effective 1 June 2025) | Identity and access management, logging and monitoring, incident response, and notifying the authority of material cyber incidents | A distinct, key-bound identity per agent; least-privilege access levels; every decision logged in a signed chain; the emergency stop and evidence packs as incident response inputs | Which agent incidents the bank classifies as material |
| **POPIA**, section 19 (security safeguards) | The responsible party secures personal information | Valet runs inside the bank and sends nothing home; receipts hold no credentials or card numbers | Personal data is still inside the receipt chain in the PoC; moving it out is scheduled before real customer data (Technical design §16) |
| **POPIA**, section 71 (automated decision-making) | No decision with legal or substantial effect based solely on automated processing that profiles a person, unless an exception applies, for example in executing a contract with appropriate measures, including a chance to make representations | Valet's checks apply the customer's own mandate; they do not profile the customer. For payments that need it, the customer confirms the exact payment. The payment evidence page shows the customer what was decided and why | Whether a refused agent payment is a section 71 decision at all; counsel's view |
| **POPIA**, section 72 (transfers abroad) | Conditions on sending personal information outside South Africa | Account data returned to an assistant hosted abroad (Claude, ChatGPT) leaves the bank at the customer's direction | Counsel's view (threat model G10); the MCP gateway's POPIA review |
| **Electronic Communications and Transactions Act**, section 15 | Data messages are admissible in evidence; their weight depends on factors including how reliably they were generated, stored and kept intact | Receipts are data messages generated at the moment of decision, signed and hash-chained; an evidence pack lets the other side check their integrity independently | How a court weighs a bank-signed record; per-grant chains and copies held by the agent operator strengthen it |

### EU and UK, for banks with operations there, or as reference

| Instrument | Relevance | What in Valet bears on it |
| --- | --- | --- |
| **EU DORA** (Regulation (EU) 2022/2554; applies from 17 January 2025) | ICT risk management, incident management and reporting, resilience testing, ICT third-party risk | The bank runs Valet itself, so Valet is not by itself an ICT third-party service; commercial support from Veridact would be one, and would go in the bank's register. The stop, reconciliation and evidence packs support incident handling; the test suite supports resilience testing |
| **UK SM&CR** | A named senior manager stays accountable; responsibility does not pass to a model or an agent | Every decision names the policy in force by the bank's change reference, and every stop records who made it, so accountability traces to people |
| **PRA SS1/23**, model risk management (effective 17 May 2024; initially for banks with internal-model approval) | Model inventory, tiering, validation | Valet's controls are deterministic rules, not a model. Keeping authority outside the model narrows what model risk management has to cover: the agent's model belongs to its operator, and the bank's control does not depend on it |
| **EU AI Act** | High-risk obligations for creditworthiness assessment and other Annex III uses now apply from 2 December 2027, after the Digital Omnibus on AI | Valet does not assess creditworthiness or profile customers. A bank that puts a credit-scoring agent behind Valet still has that agent's obligations; Valet bounds what the agent can do, not whether its use is high-risk |

## Sources

- Mervin Pearce, [Securing AI Agents in Banking](https://mervinpearce.com/securing-ai-agents-in-banking/), 17 November 2026
- SARB, [Directive 2 of 2024](https://www.gov.za/sites/default/files/gcis_document/202411/51556gon5550.pdf), Government Gazette 51556, 15 November 2024; Bowmans, [summary](https://bowmanslaw.com/insights/south-africa-new-requirement-for-issuers-of-electronic-funds-transfer-credit-payment-instructions-on-behalf-of-payers-in-the-national-payment-system-to-register-with-the-south-african-reserve-bank/)
- [Joint Standard 1 of 2023](https://lawlibrary.org.za/akn/za/act/standard/sarb/2023/1), IT governance and risk management (Laws.Africa)
- FSCA and PA, [Joint Communication 5 of 2024](https://regalert.today/document/124d5082-105f-4bf7-a872-7a128adf03e9/text): commencement of Joint Standard 2 of 2024
- Werksmans, [When machines make decisions](https://werksmans.com/when-machines-make-decisions-understanding-the-impact-of-the-protection-of-personal-information-act-2013-popia/page/43): POPIA section 71
- [Electronic Communications and Transactions Act, 2002](https://internet.org.za/ect_act.html)
- Bank of England, [SS1/23 Model risk management principles for banks](https://www.bankofengland.co.uk/prudential-regulation/publication/2023/may/model-risk-management-principles-for-banks)
- Data Protection Report, [The EU AI Act: when does it become enforceable now?](https://www.dataprotectionreport.com/2026/07/the-eu-ai-act-when-does-it-become-enforceable-now/) (July 2026)
- [Regulation (EU) 2022/2554](https://eur-lex.europa.eu/eli/reg/2022/2554/oj) (DORA)
