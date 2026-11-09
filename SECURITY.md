# Security policy

Valet is security software, so we take reports seriously, including reports about the design as well as the code.

## Reporting a vulnerability

Please report privately through GitHub: open the **Security** tab of this repository and choose
**Report a vulnerability**. Do not open a public issue for a vulnerability.

Include what you found, how to reproduce it, and what an attacker could do with it. If it is a design flaw
(for example, a way for an agent to widen its own permission, reuse an approval, or forge a receipt), a short
description of the attack is enough.

We aim to acknowledge reports within 5 working days and to agree a disclosure date with you.

## Scope

- The code in this repository: the reference bank, the agent SDK, the Keycloak extension and the tests.
- The Valet profile as specified in [`docs/technical-design.md`](docs/technical-design.md).

The demo secrets in `docker-compose*.yml`, `deploy/` and the tests (such as `marula-demo-secret` and the
`thandi` / `demo` sign-in) are deliberately public and are not vulnerabilities.

## This is a proof of concept

Version 0.1 has not had an independent security review or a run through the OpenID FAPI 2.0 conformance suite.
The README lists what a production deployment still needs. Do not use it with real customers or real money.
