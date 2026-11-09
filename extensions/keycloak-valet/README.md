# Veridact Valet extension for Keycloak

Lets a bank keep **Keycloak issuing its AI agents' tokens** while Valet keeps the rules: consent, limits,
approvals, pause and revoke, and receipts. This is Valet's native mode on Keycloak (see the main README).

It adds two things to Keycloak:

| Piece | Keycloak SPI | What it does |
|---|---|---|
| **Veridact Valet: AI agent consent** (`valet-consent`) | Authenticator | After Keycloak signs the customer in, sends them to Valet's consent screen with a signed ticket, then checks Valet's signed answer when they come back. On "allow" it records the Valet grant id in the user session; on "deny" the agent gets the standard `error=access_denied`. Runs only for clients with attribute `valet.agent=true`. |
| **Veridact Valet: grant id** (`valet-grant-mapper`) | Protocol mapper | Puts that grant id in the agent's access tokens as `valet_grant`, including refreshed ones. |

Keycloak keeps doing what it already does well: sign-in, PAR, PKCE, `private_key_jwt`, DPoP-bound tokens and
refresh. Valet's banking-API checks look up `valet_grant` on every call, so a customer pausing the agent in the bank
app stops a perfectly valid Keycloak token on its next call.

## How a connect works

```
Kaya ──PAR (private_key_jwt, PKCE, valet_level=bill_payer)──▶ Keycloak
Customer's browser ──▶ Keycloak sign-in (cookie or username + password; the bank's normal policy)
Keycloak [valet-consent] ──302 /handoff/consent?ticket=…──▶ Valet          ticket: HS256, 5 min, nonce, return address
Customer picks a level and limit on the bank's consent screen; Valet creates the grant under the bank's policy
Valet ──auto-POST valet_result=…──▶ Keycloak (same login)                   result: HS256, 2 min, same nonce, grant id
Keycloak [valet-consent] verifies signature, audience, expiry and nonce; records the grant id
Keycloak ──code──▶ Kaya ──token request (DPoP)──▶ Keycloak: access token with cnf.jkt and valet_grant
Kaya ──API call (DPoP)──▶ Valet enforcement: Keycloak's signature, issuer, audience, key binding, live grant status, limits
```

Why the hand-off rather than Keycloak's own consent screen: Keycloak has no RAR support, every IdP then shows the same
bank consent screen, the customer can choose less than the agent asked for, and the grant is created where its rules live.

## Build

```bash
KEYCLOAK_HOME=/path/to/keycloak-26.4.0 ./build.sh    # javac against your Keycloak's own libraries, no downloads
# or, with access to Maven Central:
mvn -q package
```

Either produces `target/keycloak-valet-0.1.0.jar`. Copy it to `$KEYCLOAK_HOME/providers/`, then `kc.sh build`
(or `kc.sh start-dev`, which builds automatically). Keycloak logs a KC-SERVICES0047 warning that the authenticator
and protocol-mapper SPIs are internal; that applies to every custom extension of these kinds, so re-test on each
Keycloak upgrade.

## Configure

1. **Settings.** Either set them on the `valet-consent` execution in the admin console, or as environment variables
   for Keycloak:

   | Setting | Environment variable | Example |
   |---|---|---|
   | Valet consent URL | `VALET_CONSENT_URL` | `https://valet.bank.example/handoff/consent` |
   | Valet issuer | `VALET_ISSUER` | `https://valet.bank.example` |
   | Hand-off secret (32+ characters) | `VALET_HANDOFF_SECRET` | the same value Valet has |

   On the Valet side, set `VALET_HANDOFF_SECRET` and `VALET_HANDOFF_IDPS='{"keycloak:<realm>": "<realm URL>/"}'`.
   Valet will only post results back to that address.

2. **Realm.** `deploy/keycloak/setup_native.py` does this through the admin API and can be re-run safely. It creates:
   - a flow, **valet browser**: a required sign-in sub-flow (cookie or username + password), then the required
     **Veridact Valet: AI agent consent** step;
   - an agent client, **kaya**: confidential, `private_key_jwt` with ES256 (the agent's public key as JWKS),
     DPoP-bound tokens, PAR and PKCE required, `valet.agent=true`, the flow above as its browser-flow override, and
     two mappers (`valet_grant`, and audience `marula-api`).

3. **Valet** accepts Keycloak's tokens through `VALET_EXTERNAL_ISSUERS` (issuer, JWKS URI and audience).

Approvals keep running through Valet (its CIBA endpoint), because Keycloak's CIBA cannot carry RAR. Valet binds the
grant to the agent's DPoP key on the first call, so its approval tokens only work for the same agent key.

## What has been tested

Run against **Keycloak 26.4.0** with the extension installed:

- **Connect:** Kaya connected through Keycloak (PAR, sign-in, Valet consent hand-off, DPoP token). The token was
  RS256-signed by Keycloak, with audience `marula-api`, `azp` `kaya`, a `valet_grant` and a `cnf.jkt`. Valet's own
  authorisation server issued nothing.
- **Payments and approvals:** a payment within the limit was paid; a new recipient needed approval, which was
  approved in the bank app and paid once; a beneficiary add was refused.
- **Refresh:** a 60-second Keycloak token was refreshed and kept the same grant.
- **Stopping:** pausing in the bank app stopped Kaya at once, and an IdP-side disconnect
  (`DELETE /internal/grants/{id}`) revoked the grant.
- **Customer choices:** choosing "View only" at Valet's consent made payments refuse; cancelling sent Kaya
  `error=access_denied` with no code.
- **Forgeries:** a result signed with the wrong secret ("bad signature") and a correctly signed result carrying
  another login's nonce ("does not match this login") were both refused, and Kaya got `access_denied`.

Valet's side is also covered by `tests/test_handoff.py` (14 tests).

## Not done yet

- **Asymmetric hand-off keys.** The PoC uses one shared HS256 secret in both directions. Production should have
  Keycloak sign with a realm key and Valet with its own, each verifying the other's JWKS.
- **Disconnects in Keycloak's account console.** These don't yet reach Valet. An event-listener SPI calling
  `DELETE /internal/grants/{id}` would close that. Valet already refuses calls after a bank-app disconnect.
- **One grant per agent per Keycloak user session.** A second connect by the same agent in the same session
  replaces the first.
- **Maven build.** `mvn package` was not run here (no access to Maven Central); `build.sh` was.
