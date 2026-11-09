package net.veridact.valet.keycloak;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Hands the signed-in customer to Valet's consent screen and back (native mode).
 *
 * Runs only for clients marked as AI agents (client attribute valet.agent=true). After Keycloak has signed the
 * customer in, it sends them to Valet with a short-lived signed ticket. Valet shows the bank's consent screen,
 * registers the grant under the bank's policy, and posts a signed result back here. On "allow" the grant id is
 * kept as a user-session note, which ValetGrantMapper puts in the agent's access tokens. On "deny" the agent gets
 * the standard OAuth error access_denied.
 */
public class ValetConsentAuthenticator implements Authenticator {
    static final String AGENT_ATTRIBUTE = "valet.agent";
    static final String NONCE_NOTE = "valet.nonce";
    static final String LEVEL_PARAM_NOTE = "client_request_param_valet_level";   // ?valet_level=... on the request

    private static final Logger LOG = Logger.getLogger(ValetConsentAuthenticator.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    static String grantNote(String clientId) {
        return "valet.grant." + clientId;
    }

    static String audience(RealmModel realm) {
        return "keycloak:" + realm.getName();
    }

    @Override
    public void authenticate(AuthenticationFlowContext ctx) {
        AuthenticationSessionModel auth = ctx.getAuthenticationSession();
        ClientModel client = auth.getClient();
        if (!"true".equals(client.getAttribute(AGENT_ATTRIBUTE))) {
            ctx.success();                                   // ordinary applications are untouched
            return;
        }
        ValetSettings s = ValetSettings.from(ctx.getAuthenticatorConfig());
        UserModel user = ctx.getUser();
        byte[] n = new byte[24];
        RANDOM.nextBytes(n);
        String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(n);
        auth.setAuthNote(NONCE_NOTE, nonce);

        long now = System.currentTimeMillis() / 1000;
        Map<String, Object> ticket = new HashMap<>();
        ticket.put("iss", audience(ctx.getRealm()));
        ticket.put("aud", s.valetIssuer());
        ticket.put("iat", now);
        ticket.put("exp", now + 300);
        ticket.put("nonce", nonce);
        ticket.put("customer", user.getUsername());
        if (user.getEmail() != null) ticket.put("email", user.getEmail());
        ticket.put("client_id", client.getClientId());
        String level = auth.getClientNote(LEVEL_PARAM_NOTE);
        if (level != null) ticket.put("requested_level", level);
        ticket.put("return_to", ctx.getActionUrl(ctx.generateAccessCode()).toString());

        String to = UriBuilder.fromUri(s.consentUrl()).queryParam("ticket", HandoffToken.sign(ticket, s.secret())).build().toString();
        ctx.challenge(Response.seeOther(java.net.URI.create(to)).build());
    }

    @Override
    public void action(AuthenticationFlowContext ctx) {
        AuthenticationSessionModel auth = ctx.getAuthenticationSession();
        ValetSettings s = ValetSettings.from(ctx.getAuthenticatorConfig());
        MultivaluedMap<String, String> form = ctx.getHttpRequest().getDecodedFormParameters();
        Map<String, Object> result;
        try {
            result = HandoffToken.verify(form.getFirst("valet_result"), s.secret(), audience(ctx.getRealm()));
            String nonce = auth.getAuthNote(NONCE_NOTE);
            if (nonce == null || !nonce.equals(result.get("nonce"))) throw new IllegalArgumentException("hand-off result does not match this login");
            if (!s.valetIssuer().equals(result.get("iss"))) throw new IllegalArgumentException("hand-off result not from Valet");
        } catch (IllegalArgumentException e) {
            LOG.warnf("Valet consent hand-off rejected: %s", e.getMessage());
            ctx.failure(AuthenticationFlowError.ACCESS_DENIED, sendError(ctx, auth));
            return;
        }
        auth.removeAuthNote(NONCE_NOTE);                        // single use
        Object grant = result.get("grant_id");
        if ("allow".equals(result.get("decision")) && grant instanceof String g && !g.isBlank()) {
            auth.setUserSessionNote(grantNote(auth.getClient().getClientId()), g);
            ctx.success();
        } else {
            ctx.failure(AuthenticationFlowError.ACCESS_DENIED, sendError(ctx, auth));
        }
    }

    /** Send the agent the standard OAuth error (access_denied) rather than leaving the customer on an error page. */
    private static Response sendError(AuthenticationFlowContext ctx, AuthenticationSessionModel auth) {
        KeycloakSession session = ctx.getSession();
        LoginProtocol protocol = session.getProvider(LoginProtocol.class, auth.getProtocol());
        protocol.setRealm(ctx.getRealm()).setHttpHeaders(session.getContext().getRequestHeaders())
                .setUriInfo(ctx.getUriInfo()).setEventBuilder(ctx.getEvent());
        return protocol.sendError(auth, LoginProtocol.Error.CONSENT_DENIED, null);
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
