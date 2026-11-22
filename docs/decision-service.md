# Valet decision service: AuthZEN interface, reservations and the shared store

Draft v0.1 · 22 November 2026 · Design, not yet built. Today the proof of concept runs these checks in-process
(`valet/bank/payments.py`, `valet/bank/mcp.py`); this document is how they become a service the bank calls.

## Summary

Valet runs **beside** the bank's own systems, not in front of them. The bank owns the MCP server, the APIs, the
authorization server and the payment system. Those are the **enforcement points**. Valet is the **decision point**
they ask, over the OpenID AuthZEN Authorization API 1.0 (a Final Specification since January 2026), with a small
extension for money: **reserve, commit and release**.

```
 agent ──► bank's MCP server or API  (enforcement point, owned by the bank)
                │  1. POST /access/v1/evaluation       "may this agent pay R450 to City Power?"
                ▼
           Valet decision service    (decision point, run by the bank, beside its systems)
                │  shared store: mandates, usage, reservations, idempotency keys, receipts
                ▲  3. POST /valet/v1/reservations/{id}/commit | release
                │
 bank's MCP server ──2. executes with its own payment system, reservation id as idempotency key──► payments
```

Valet never moves money. It decides, holds the amount against the mandate, and records what happened. The bank
executes.

## Deployment

The API is the same in both shapes. Only the network hop differs.

| Shape | When | Notes |
|---|---|---|
| **Separate internal service** (recommended) | Production | Several stateless Valet instances behind an internal load balancer, all on one shared store. Enforcement points call it over mTLS. |
| **Sidecar container** | A bank that wants it in the same pod as its MCP server | Same image, same API on localhost. It **must** still use the shared store; never a per-pod database, or two pods would each let a payment through under the same limit. |

The store is always shared. Valet instances keep nothing that matters in memory: they can be killed, scaled or
restarted at any time.

Calls from enforcement points are authenticated with mTLS or `private_key_jwt`, and only the bank's own
enforcement points may call. **Fail closed:** if Valet does not answer within the timeout (target: 300 ms at p99),
the enforcement point refuses the action. It never assumes "allow".

## Interface 1: AuthZEN evaluation (every action)

Endpoint: `POST /access/v1/evaluation`, discovered from `/.well-known/authzen-configuration`
(`access_evaluation_endpoint`). A deny is a `200` with `"decision": false`, not an HTTP error.

### Request

| AuthZEN member | Valet meaning |
|---|---|
| `subject` | The agent: `{"type":"agent","id":"<client_id>","properties":{"grant":"<grant id>","customer":"<pairwise id>","actor":{…Veridact result…},"token":{"jkt":"…","tier":"bearer"|"dpop"}}}` |
| `action` | The operation: `{"name":"pay_existing_beneficiary"}`, `view_balance`, `list_payees`, … |
| `resource` | The account: `{"type":"account","id":"<account id>"}` |
| `context` | The facts of this call: `payment` (payee, amount, currency), `idempotency_key`, `channel` (`mcp` / `api`), the agent's stated reason (labelled agent-supplied) |

Example: a payment

```json
{
  "subject":  {"type": "agent", "id": "https://claude.ai/oauth/mcp-client-metadata",
               "properties": {"grant": "g_7Hq2", "customer": "ps_91ac", "token": {"tier": "bearer"}}},
  "action":   {"name": "pay_existing_beneficiary"},
  "resource": {"type": "account", "id": "acc_cheque_1"},
  "context":  {"payment": {"payee": "ben_city_power", "amount": "450.00", "currency": "ZAR"},
               "idempotency_key": "c1f0e6a2-…", "channel": "mcp",
               "agent_reason": "Monthly electricity bill"}
}
```

### Response

Everything Valet-specific sits under `context.valet`. AuthZEN lets a PEP refuse a `true` decision whose context
it does not understand. Valet relies on that: an enforcement point that cannot read `context.valet` must not move
money.

| Outcome | `decision` | `context.valet` |
|---|---|---|
| Allowed, nothing to hold (for example `view_balance`) | `true` | `{"outcome":"allowed","receipt":"…"}` |
| Payment within the mandate | `true` | `{"outcome":"reserved","reservation":"r_…","expires_at":"…","receipt":"…"}` |
| Needs the customer | `false` | `{"outcome":"approval_required","reason":"over_per_payment","reservation":"r_…","approval":{…challenge…}}` |
| Refused | `false` | `{"outcome":"declined","reason":"payee_not_on_mandate","receipt":"…"}` |

Reasons are the seven from the Internet-Draft, applied in its fixed order.

### Tool lists: batch evaluation

`POST /access/v1/evaluations` answers "which of these tools may this agent see?" in one call, so the bank's MCP
server filters `tools/list` by the live mandate. Use `"evaluations_semantic":"execute_all"`; nothing is reserved
in a batch.

## Interface 2: the Valet reservation extension (money only)

A plain allow/deny is not enough for money. Limits are counters: two payments checked at the same moment could
both pass a limit only one of them fits under. So an allowed payment comes back **reserved**. The amount is held
against the mandate until the bank reports what happened.

Endpoints, advertised in the AuthZEN metadata as `valet_reservations_endpoint` (AuthZEN tells receivers to
ignore members they don't know, so this is compatible):

| Call | Sent when | Effect |
|---|---|---|
| `POST /valet/v1/reservations/{id}/sent` | The enforcement point is about to hand the payment to the bank's payment system | `reserved` → `sent`. From here the hold is **never** released on a timer. |
| `POST /valet/v1/reservations/{id}/commit` `{"bank_payment_id":"…"}` | The bank accepted the payment | → `committed`; usage moves from held to spent; receipt written |
| `POST /valet/v1/reservations/{id}/release` `{"reason":"declined"|"cancelled"|"not_sent"}` | The bank declined it, or it was never sent | → `released`; the hold is returned to the limit; receipt written |
| `POST /valet/v1/reservations/{id}/unknown` | The bank did not answer (timeout) | → `unknown`; **still held** and counted against the limit until the bank's answer is known |
| `GET /valet/v1/reservations/{id}` | Recovery after a crash | Current state, so the enforcement point can carry on |

Rules:

- **The reservation id is the idempotency key the enforcement point gives the bank's payment system.** A retry
  after a crash re-sends the same id, and the bank answers with the original result.
- A reservation never sent expires after its `expires_at` (default 10 minutes), and the hold is released. That is
  safe because no money could have moved.
- Every call is idempotent: `commit` twice returns the same result; `commit` after `release` is a `409`.
- An approval (`approval_required`) is bound to its reservation. When the customer approves, the same reservation
  becomes `reserved` and the flow continues. An approval can never be reused for another payment.

```
evaluation ─► reserved ─► sent ─► committed
    │            │          ├──► released (declined)
    │            │          └──► unknown ──► committed | released   (only on the bank's answer)
    │            └──► released (not sent, or expired)
    └─► approval_required ─(customer approves)─► reserved
```

These are the PoC's payment-intent states (`valet/bank/payments.py`), with the enforcement point reporting
progress instead of Valet calling the core banking system.

**Optional instruct mode.** A bank that would rather Valet sent the instruction keeps today's core-banking adapter
(`valet/bank/core.py`). The states and the store are the same; only who calls the payment system changes.

## The shared store

### Recommendation: a relational database with ACID transactions, PostgreSQL as the reference

The decisions Valet makes are small, frequent read-check-write transactions on money limits. They need four
properties together:

1. **Atomic read-check-write:** read the mandate's usage, check the limit, write the hold, all or nothing.
2. **Row-level locks:** serialise decisions for one mandate without slowing anyone else's.
3. **Unique constraints:** a duplicate request must fail at the database, not in application code.
4. **Durability with zero data loss on failover:** a committed hold must survive the primary dying.

| Option | Fit | Why |
|---|---|---|
| **PostgreSQL** | **Reference** | All four, simply: `SELECT … FOR UPDATE`, unique indexes, synchronous replication. Widely run by banks, and available managed (Azure Database for PostgreSQL, Amazon RDS / Aurora). Open source, matching Valet. |
| Oracle, SQL Server | Supported | The same patterns work. Many banks standardise on one of these; the data-access layer should stay portable SQL so a bank can use its own. |
| DynamoDB, Cosmos DB | Possible, not preferred | Conditional writes and transactions exist, but multi-row limit checks and hash-chained receipts are harder to get right, and harder for a bank's DBAs to audit. |
| Redis | Cache only | Fine for caching Veridact status lists or token introspection. Never the system of record for holds: its durability and failover can lose acknowledged writes. |
| Cassandra or other eventually consistent stores | No | "Eventually" isn't good enough for a spending limit. |

Run decisions only against the **primary**. Use a synchronous standby (zero data loss), and never read from an
asynchronous replica for a decision: a lagging replica could miss a hold that was just written.

### Tables (outline)

| Table | Holds | Key constraints |
|---|---|---|
| `mandates` | Grant, customer, agent, level, limits, status, version | Primary key `id`; status `active`, `paused` or `revoked` |
| `mandate_usage` | Per mandate and period: committed amount and count, held amount and count | Primary key `(mandate_id, period)`; this is the **row that gets locked** |
| `reservations` | One per payment the agent asks for: state, amount, payee, digest of the request, bank payment id | Unique `(mandate_id, idempotency_key)` |
| `approvals` | Pending customer approvals, bound to a reservation | Unique `reservation_id`; single use |
| `receipts` | Signed, hash-chained decision records | Append-only; see below |
| `receipt_heads` | The latest hash of each chain | Locked on append |
| `outbox` | Events for the bank (payment held, mandate paused) | Written in the same transaction; delivered at least once |

## Concurrency and idempotency: the cases that matter

### Case 1: the same payment arrives twice (a retry)

The agent, the MCP platform or the bank's server retries after a timeout, so two identical requests arrive
milliseconds apart.

```sql
INSERT INTO reservations (id, mandate_id, idempotency_key, request_digest, state, amount, …)
VALUES (…)
ON CONFLICT (mandate_id, idempotency_key) DO NOTHING
RETURNING id;
```

- The first insert wins. The second inserts nothing, reads the existing row, and returns **the same reservation
  and the same decision**. It reserves nothing new.
- If the second request has the same key but a **different digest** (a different payee or amount), it is refused
  (`409`, `idempotency_key_reused`). One key can never cover two payments.
- The idempotency key is scoped to the mandate, because two customers using the same agent may happen to send the
  same key.

### Case 2: two different payments at the same moment, and only one fits under the limit

The customer's limit has R1,000 left. The agent sends R700 to City Power and R600 to the school at the same time.

```sql
BEGIN;
SELECT * FROM mandates      WHERE id = :m FOR UPDATE;                       -- status and limits, locked
SELECT * FROM mandate_usage WHERE mandate_id = :m AND period = :p FOR UPDATE;
-- check: committed + held + this amount <= period limit; count likewise; per-payment cap; payee on mandate
INSERT INTO reservations (…) …;
UPDATE mandate_usage SET held_amount = held_amount + :amt, held_count = held_count + 1 WHERE …;
INSERT INTO receipts (…) …;
COMMIT;
```

- The two transactions queue on the mandate's lock. The first reserves R700; the second sees R300 left and gets
  `approval_required` with reason `over_period_limit`.
- Only that one mandate is serialised. Every other customer's payments run in parallel.
- **Held amounts count against the limit** (`reserved`, `sent`, `unknown`). Otherwise an agent could queue twenty
  "pending" payments to get around the monthly count.
- Lock order is always mandate, then usage, then receipt head, so two transactions can never deadlock each other.

### Case 3: the customer revokes or pauses while a payment is in flight

The pause takes the **same mandate lock**, so it is ordered cleanly against every decision:

| Payment state when the pause commits | What happens |
|---|---|
| Not yet evaluated | Refused (`declined`, reason `mandate_paused`) |
| `reserved` or `approval_required` (never sent) | Released at once; receipt says cancelled by the customer |
| `sent` or `unknown` (may have reached the bank) | Stays held. The bank's answer decides: commit or release. An outbox event asks the bank's cancel-or-confirm process to try to stop it. |

The point of no return is the bank accepting the payment, exactly as in the PoC today.

### Case 4: a crash between steps

| Crash point | Recovery |
|---|---|
| After `reserved`, before `sent` | The enforcement point reads the reservation back and carries on, or it expires and releases (no money moved) |
| After `sent`, before the bank answers | The enforcement point retries with the same reservation id as the bank's idempotency key; the bank returns the original result; it reports `commit` or `release` |
| After the bank accepted, before `commit` | Same: the retry returns "already accepted", and the enforcement point commits |
| Valet instance dies mid-transaction | The database rolls back; nothing half-done is visible; the enforcement point retries the evaluation with the same idempotency key |

`unknown` reservations older than a set time go to an operations queue, still held. **Nothing is released on a
timer once it may have been sent.**

### Case 5: the enforcement point forgets to ask

A sidecar can only enforce what it is asked about. Three controls:

1. **Fail closed** in the enforcement point (no decision means no payment).
2. **PEP conformance tests** in the repo, which a bank runs against its own MCP server and APIs.
3. **Reconciliation:** Valet compares the bank's payments feed with its committed reservations, and raises an alert
   on any agent payment with no matching decision.

## Receipts under concurrency

A hash chain needs one writer at a time per chain. The receipt is written in the **same transaction** as the
decision, appending after the chain head, which is locked (`receipt_heads … FOR UPDATE`). So a receipt exists if
and only if the decision does.

One global chain (today's PoC) makes the chain head a hot spot at scale. The planned per-mandate chains (deferred
in the technical design) remove it, because each mandate's chain head is locked together with the mandate anyway.
Chain heads are still published periodically, so truncation can be detected.

## What the enforcement point must do

A checklist for the bank's developers. The reference MCP server (`valet/bank/mcp.py`, an example) shows each step.

1. Validate the access token, and pass the grant id and token facts to Valet.
2. Call `evaluation` before **every** action. Fail closed on timeout or error.
3. Refuse a `true` decision whose `context.valet` it does not understand.
4. For money: call `sent` before handing the payment to the payment system, use the reservation id as that
   system's idempotency key, then report `commit`, `release` or `unknown`.
5. Never retry a payment under a new idempotency key.
6. Pass the agent's stated reason through, labelled as agent-supplied.
7. Run the PEP conformance tests in CI.

## Open questions

- Align `subject` and `action` names with the AuthZEN MCP tool-authorization profile, and approvals with the
  AuthZEN Access Request and Approval Profile, once read in detail.
- Decision latency target per bank (300 ms p99 is a starting point).
- Whether the reservation extension should be proposed to the AuthZEN working group as a profile.

## References

- [OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0-final.html) (Final, January 2026)
- [AuthZEN working group specifications](https://openid.net/wg/authzen/specifications/), including the MCP and approval profiles
- [Technical design](technical-design.md), section 5.1 (payment intents)
- [MCP gateway design](mcp-gateway-design.md)
