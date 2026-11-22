# Contributing

Thanks for your interest in Valet. Contributions are welcome from banks, identity and security engineers,
agent builders, lawyers and risk people.

## The most useful contributions right now

- **Find the flaws.** Ways an agent could exceed what the customer allowed, or a dispute that the receipts
  could not settle. Security issues go through [SECURITY.md](SECURITY.md), not public issues.
- **Identity provider support.** Native-mode hooks for Auth0, PingFederate, Okta, Curity and others (see §12 of
  the [technical design](docs/technical-design.md)).
- **Design feedback.** Open an issue that names the section of `docs/` you are commenting on.

## Working on the code

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt pytest
python -m pytest -q      # 145 tests
python demo.py           # 24 checks; exits non-zero if any protection fails
```

Every pull request should keep the tests and the demo passing. A change to how a check, approval or receipt
works should change the design doc in the same pull request.

## Sign your commits (DCO)

This project uses the [Developer Certificate of Origin](https://developercertificate.org/) (DCO) instead of a
contributor licence agreement. There is nothing to sign up for: add a `Signed-off-by` line to each commit to
confirm that you wrote the change, or have the right to submit it, under this project's licence.

```bash
git commit -s -m "Explain what changed"
```

This adds `Signed-off-by: Your Name <you@example.com>`, using your git name and email. A check on every pull
request confirms that each commit is signed off. If you forget, `git commit --amend -s` fixes the latest
commit, and `git rebase --signoff main` fixes them all.

If you contribute as part of your job, check that your employer allows it. The DCO is designed to be easy for
company legal teams to approve.

## How decisions are made

See [GOVERNANCE.md](GOVERNANCE.md). Changes to how a check, approval or receipt works need two maintainer
approvals and stay open for at least 7 days. Changes that affect interoperability are also discussed against
the [Internet-Draft](https://datatracker.ietf.org/doc/draft-craig-oauth-rar-payment-mandates/) on the IETF
OAuth working group list (oauth@ietf.org).

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Licence

By contributing, you agree that your contribution is licensed under the Apache License 2.0, the licence of
this project. The project's names are covered separately in [TRADEMARKS.md](TRADEMARKS.md).
