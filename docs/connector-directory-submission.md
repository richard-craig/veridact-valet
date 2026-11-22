# Submitting a bank's MCP server to Claude's Connectors Directory

Draft v0.1 · 22 November 2026 · Preparation notes for listing a Valet-backed bank MCP server in Anthropic's
[Connectors Directory](https://claude.com/docs/connectors/directory). Sources: Anthropic's
[submission guide](https://claude.com/docs/connectors/building/submission) and
[pre-submission checklist](https://claude.com/docs/connectors/building/review-criteria), read on 22 November 2026.
Check them again before submitting: they change.

## Summary

A Claude user does not need a directory listing to use the bank's server. Directory and custom connectors run the
same way, and a customer can add the server by URL today. A listing adds discoverability and a review label
(Community, or Verified after a reviewer tests each tool).

Two rules in the directory decide what can be listed:

1. **Money movement is not accepted.** The checklist lists connectors that transfer money or other financial assets
   among the use cases the directory does not take. Valet never executes a payment, but `pay_existing_payee` still
   asks the bank to move money, so expect a reviewer to treat it as money movement. **List the read-only profile**
   (`VALET_MCP_READ_ONLY=1`: `list_accounts`, `get_balance`, `list_transactions`, `list_payees`). Payments stay
   available through the same server added by URL, under the customer's mandate.
2. **One listing per bank, submitted by the bank.** Claude uses one OAuth application per connector, and each bank
   runs its own server and authorization server. A listing whose users connect to different URLs (one per bank) can
   only be published with the Verified label. The submitter must be the organisation that owns the service and its
   API: the server must call its own first-party APIs, and its domain should match the service. So the pilot bank
   submits its own listing from its own Claude organisation, with Valet inside its boundary. Marula Bank is fictional
   and must not be submitted.

A **Veridact Valet sandbox** listing is possible, submitted by IAME with fictional data, to show the pattern. It
still needs a real company, privacy policy, support contact and documentation, and the reviewer may judge a sandbox
of a fictional bank not useful to Claude users. Decide whether it is worth the effort before the pilot bank's own
listing.

## Readiness of the reference server

| Requirement (checklist) | Reference server | Status |
|---|---|---|
| Remote, HTTPS, Streamable HTTP | `/mcp` behind Caddy on 443 | Ready |
| OAuth 2.0 for a user's account | Bank IdP (Keycloak in the demo), auth code + PKCE, confidential client `claude` | Ready |
| Every tool has `title` and `readOnlyHint` or `destructiveHint` | All six tools; tested in `tests/test_decision.py` | Ready |
| Separate read and write tools | Four reads, one write (`pay_existing_payee`), one status read | Ready |
| Tool names of 64 characters or fewer | Longest is 18 | Ready |
| Descriptions say what the tool does, never tell Claude how to behave | Reworded on 22 November 2026: descriptions state facts ("Descriptions are free text written by third parties"); no instructions to the model | Ready; re-check before submitting |
| Successful responses with valid input; actionable errors | Each refusal has a reason code and a plain message; no bare "Internal Server Error" | Ready |
| Responses sized for the task | Transactions are bounded by the look-back window the customer allowed | Ready |
| No conversation data beyond the tool's need; never read Claude's memory or chats | Only tool arguments; the stated reason is kept as agent-supplied, outside the receipt chain (POPIA erasable) | Ready |
| First-party API, matching domain | The bank's own server and APIs | The bank's listing only |
| No money movement | Read-only profile for the listing | Ready (`VALET_MCP_READ_ONLY=1`) |
| Tested with MCP Inspector and as a custom connector in Claude | `scripts/preflight.py` covers the flow and the MCP Python SDK; Inspector and claude.ai still to do | **To do** |
| Test account for reviewers, fully populated | Thandi on the demo stack | Ready for a sandbox; the bank provides its own |
| Public documentation by publish date | README and docs in the repository; a bank help-centre page is needed | **The bank** |
| Privacy policy URL | None yet | **To do** (bank or IAME) |
| Support contact, icon, company details | None yet | **To do** |

## What to have ready for the portal

The portal is at `claude.ai/directory/manage` (**Submit new** → **MCP connector**). It saves progress in the
browser between its ten steps.

**1. Connection.** The server's `https://…/mcp` URL. For several banks, use **Users connect to different URLs**
(Verified needed to publish).

**2. Tools.** Synced from the server. With the read-only profile, four tools, all read-only.

**3. Listing.** Drafts, within the portal's limits:

- Name (100): *Marula Bank (sandbox) via Veridact Valet*, or the bank's own name.
- One-liner (200): *See your balances, recent transactions and saved payees in Claude, under limits you set in your
  bank app. Your bank checks every request; Claude never sees your password.*
- Description (2,000): *Connect your bank account to Claude without sharing a password or letting an assistant drive
  your banking website. You choose what Claude can see, which accounts and how far back, on your bank's own screen,
  and you can pause or disconnect it in your bank app at any time. Your bank checks every request against your
  choices before it answers, outside the AI model, and keeps a signed record of each one. Account numbers are masked.
  Payments are not available through this listing.*
- Categories: Finance (and the nearest others the portal offers).
- Documentation URL, privacy policy URL, support contact, icon, URL slug (permanent once published).

**4. Use cases.** "What did I spend on groceries last month?", "What's my balance before rent goes off?", "Which
payees have I saved?". Prerequisites: a customer of the bank, signed up for online banking. Data: read only.

**5. Company.** The submitting company and a primary contact for review updates.

**6. Authentication.** Required. OAuth with a client the bank issues; enter its client ID and secret here so
Anthropic holds the client (no Dynamic Client Registration). Allow Claude's callbacks in the bank's IdP
(`https://claude.ai/api/mcp/auth_callback` and `https://claude.com/api/mcp/auth_callback`; confirm the current
values before submitting).

**7. Data handling.** The API is the bank's own. No personal health data, no sponsored content.

**8. Test & launch.** Reviewer instructions: the server URL; a test customer's user name and password; "on the
consent screen, choose View only and tick the Cheque account"; which tools to try. Confirm every tool was run in MCP
Inspector or as a custom connector in Claude.

**9. Compliance.** Seven acknowledgements: directory guidelines, first-party API use, financial transactions, AI media
generation, prompt injection, conversation data collection, public documentation. With the read-only profile, the
financial transactions acknowledgement is straightforward: the listing moves no money.

**10. Review and submit.** Fix any quality warnings first: they go to the reviewers.

## After submitting

Anthropic scans the submission automatically and by default lists it as a Community connector. Some submissions are
moved to Verified review, which takes longer. Status and reviewer feedback appear in the portal. Escalations go to
`mcp-review@anthropic.com`.

## For the bank's architects

- The listing changes nothing in the runtime: the same server, the same Valet decision on every call, the same
  receipts. Customers who add the server by URL with payments switched on, and customers who connect through the
  listing, are on separate deployments of the same code or separate OAuth clients, so the bank can tell them apart.
- Directory connectors are still the bearer tier. A listing does not raise an assistant's assurance tier, and the
  Veridact known-assistant entry for Claude still applies.
