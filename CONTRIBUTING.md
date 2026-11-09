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
python -m pytest -q      # 49 tests
python demo.py           # 22 checks; exits non-zero if any protection fails
```

Every pull request should keep the tests and the demo passing. A change to how a check, approval or receipt
works should change the design doc in the same pull request.

## Licence

By contributing, you agree that your contribution is licensed under the Apache License 2.0, the licence of
this project.
