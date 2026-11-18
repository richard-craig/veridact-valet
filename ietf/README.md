# IETF Internet-Draft: payment mandates, approval reasons and receipts

`draft-craig-oauth-rar-payment-mandates-00` takes the Valet profile ([docs/valet-profile.md](../docs/valet-profile.md)) and puts it in neutral form for the IETF OAuth working group (Web Authorization Protocol). It is meant to work alongside `draft-rosomakho-oauth-txn-challenge`, not compete with it.

| File | Use |
| --- | --- |
| `draft-craig-oauth-rar-payment-mandates-00.xml` | The source (RFCXML v3). Upload this one |
| `.txt`, `.html` | Built with `xml2rfc --v3 --text --html` (xml2rfc 3.35) |

## How the draft maps to Valet

| Draft | Valet |
| --- | --- |
| `payment_mandate` | `valet_payments` |
| `single_payment` | `valet_payment_once` |
| `approval: every_payment` / `within_limits` | `approved_payer` / `bill_payer` |
| `limits.per_period` (`period`: day, week, month) | `limits.per_month` (month only) |
| reasons `every_payment`, `over_period_count`, `over_period_limit` | `approved_payer`, `over_monthly_count`, `over_monthly_limit` |
| receipt `payment` kept outside the chain | still `detail`, inside the chain |

When the draft settles, the profile adopts its names and keeps the old ones as aliases.

## Submitting

1. Sign in to the Datatracker (create an account first if needed).
2. Upload the `.xml` at https://datatracker.ietf.org/submit/. The tool runs idnits; fix anything it flags and upload again.
3. Confirm the submission from the email the Datatracker sends to the author address.
4. Announce it on oauth@ietf.org with a short note: the problem, the relationship to the transaction challenge draft, a link to the running code, and a request for review. Copy the challenge draft's authors.
5. Ask the OAuth chairs for a few minutes at the next interim or IETF meeting.
