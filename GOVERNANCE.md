# Governance

Valet is open infrastructure that banks and other organisations run themselves. That only works if no single
person or company can hold the project hostage, including its founder. This document says how decisions are
made, how people earn a say, and how the project outlives any one contributor.

## Principles

1. **Open by default.** Design discussions, decisions and their reasons happen in public issues and pull
   requests. Security reports are the exception (see [SECURITY.md](SECURITY.md)).
2. **Standards first.** Where Valet defines something others must interoperate with (mandate types, approval
   reasons, error codes, receipts), the definition lives in an open specification, currently the IETF
   Internet-Draft
   [draft-craig-oauth-rar-payment-mandates](https://datatracker.ietf.org/doc/draft-craig-oauth-rar-payment-mandates/).
   The code follows the specification, not the other way round. When the IETF working group changes the
   specification, the code changes to match.
3. **No lock-in.** Valet must keep working on more than one identity platform. A change that ties it to one
   vendor's product will not be merged.
4. **Deployers stay in charge.** Nothing in Valet calls home or sends data to the project or to any company.

## Roles

| Role | Who | What they can do |
|---|---|---|
| **Contributor** | Anyone who opens an issue or pull request | Propose changes, review, take part in discussion |
| **Maintainer** | Listed in [MAINTAINERS.md](MAINTAINERS.md) | Review and merge pull requests, triage issues, cut releases |
| **Lead maintainer** | Listed in [MAINTAINERS.md](MAINTAINERS.md) | Breaks ties, and acts for the project until the steering group exists |

### Becoming a maintainer

A contributor becomes a maintainer after sustained, good-quality contributions (code, review, specification
or test work) over at least three months. An existing maintainer nominates them in a public issue. They are
added if no maintainer objects within 14 days, or by a majority of maintainers if someone does.

Maintainers who are inactive for 12 months move to emeritus status. They can return by asking.

### Spread of maintainers

The project aims to have maintainers from **at least three different organisations**, and **no single
organisation holding a majority** of maintainer seats. Until it does, the lead maintainer will actively seek
maintainers from deploying organisations, identity-platform vendors and independent contributors.

## How decisions are made

- **Everyday changes** (fixes, tests, docs, refactors): one maintainer approval, and the tests and demo pass.
- **Significant changes** (anything that changes a check, an approval, a receipt, the data model, a public API
  or the specification): two maintainer approvals, preferably from different organisations, and the pull
  request stays open for at least 7 days. The design doc changes in the same pull request.
- **Lazy consensus:** if no maintainer objects within the review period, the change can proceed. An objection
  must give a reason and, where possible, an alternative.
- **Disagreement:** discuss in the issue first. If maintainers can't agree, they vote and a simple majority
  decides. The lead maintainer breaks ties until the steering group exists.
- **Specification changes** are proposed in this repository and on the IETF OAuth working group list
  (oauth@ietf.org). Where the working group reaches a different consensus, the working group's text wins.

## Steering group

Once there are at least three maintainers from at least two organisations, they form a steering group that
takes over the lead maintainer's tie-breaking role, approves changes to this document, and decides on joining
a neutral foundation. No organisation may hold more than one third of steering-group seats.

## Changing this document

Changes to this document need two thirds of maintainers to agree, with the pull request open for at least 14
days.

## Name and trademark

The code is licensed under Apache 2.0 and belongs to everyone. The names "Veridact" and "Veridact Valet" are
held separately so that people can rely on what carries the name. See [TRADEMARKS.md](TRADEMARKS.md).

## Code of conduct

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).
