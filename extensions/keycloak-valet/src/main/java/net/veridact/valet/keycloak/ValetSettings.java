package net.veridact.valet.keycloak;

import org.keycloak.models.AuthenticatorConfigModel;

import java.util.Map;

/** Where Valet is and the hand-off secret: from the execution's config in the admin console, else environment. */
record ValetSettings(String consentUrl, String valetIssuer, String secret) {
    static final String CONSENT_URL = "valet.consent.url";
    static final String ISSUER = "valet.issuer";
    static final String SECRET = "valet.handoff.secret";

    static ValetSettings from(AuthenticatorConfigModel model) {
        Map<String, String> c = model == null || model.getConfig() == null ? Map.of() : model.getConfig();
        String url = pick(c.get(CONSENT_URL), System.getenv("VALET_CONSENT_URL"));
        String iss = pick(c.get(ISSUER), System.getenv("VALET_ISSUER"));
        String secret = pick(c.get(SECRET), System.getenv("VALET_HANDOFF_SECRET"));
        if (url == null || iss == null || secret == null || secret.length() < 32) {
            throw new IllegalStateException("Valet consent hand-off is not configured (consent URL, issuer, and a secret of 32+ characters)");
        }
        return new ValetSettings(url, iss, secret);
    }

    private static String pick(String a, String b) {
        return a != null && !a.isBlank() ? a : (b != null && !b.isBlank() ? b : null);
    }
}
