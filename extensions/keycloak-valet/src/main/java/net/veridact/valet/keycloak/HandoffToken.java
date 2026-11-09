package net.veridact.valet.keycloak;

import org.keycloak.util.JsonSerialization;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;

/**
 * Compact HS256 JWTs for the hand-off between Keycloak and Valet.
 *
 * PoC choice: one shared secret, both directions. A bank deployment should switch to asymmetric keys
 * (Keycloak signs with a realm key, Valet with its own, each verifying via the other's JWKS).
 */
final class HandoffToken {
    private static final Base64.Encoder ENC = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DEC = Base64.getUrlDecoder();
    private static final String HEADER = ENC.encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));

    private HandoffToken() {}

    static String sign(Map<String, Object> claims, String secret) {
        try {
            String body = ENC.encodeToString(JsonSerialization.writeValueAsString(claims).getBytes(StandardCharsets.UTF_8));
            String input = HEADER + "." + body;
            return input + "." + ENC.encodeToString(mac(secret, input));
        } catch (Exception e) {
            throw new IllegalStateException("could not sign hand-off token", e);
        }
    }

    /** Verifies signature, algorithm, audience and expiry. Throws IllegalArgumentException with a safe message. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> verify(String token, String secret, String expectedAudience) {
        if (token == null) throw new IllegalArgumentException("missing hand-off result");
        String[] parts = token.split("\\.");
        if (parts.length != 3) throw new IllegalArgumentException("malformed hand-off result");
        try {
            Map<String, Object> header = JsonSerialization.readValue(new String(DEC.decode(parts[0]), StandardCharsets.UTF_8), Map.class);
            if (!"HS256".equals(header.get("alg"))) throw new IllegalArgumentException("unexpected algorithm");
            byte[] expected = mac(secret, parts[0] + "." + parts[1]);
            if (!MessageDigest.isEqual(expected, DEC.decode(parts[2]))) throw new IllegalArgumentException("bad signature");
            Map<String, Object> claims = JsonSerialization.readValue(new String(DEC.decode(parts[1]), StandardCharsets.UTF_8), Map.class);
            Object exp = claims.get("exp");
            if (!(exp instanceof Number) || ((Number) exp).longValue() < System.currentTimeMillis() / 1000) {
                throw new IllegalArgumentException("hand-off result expired");
            }
            if (!expectedAudience.equals(claims.get("aud"))) throw new IllegalArgumentException("hand-off result for someone else");
            return claims;
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("unreadable hand-off result");
        }
    }

    private static byte[] mac(String secret, String input) throws Exception {
        Mac m = Mac.getInstance("HmacSHA256");
        m.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return m.doFinal(input.getBytes(StandardCharsets.UTF_8));
    }
}
