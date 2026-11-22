package net.veridact.valet.keycloak;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Puts the Valet grant id (recorded by ValetConsentAuthenticator) in the agent's access token as "valet_grant".
 * Refreshed tokens carry it too, because it lives in the user session. Valet's enforcement looks the grant up on
 * every call, so pause, revoke and limits apply to Keycloak's tokens exactly as to Valet's own.
 *
 * It also adds an RFC 8693 actor claim, "act": {"sub": "<client id>"}, so the token says in standard form that the
 * client acts for the customer named in "sub" (delegation, not impersonation). The bank's MCP server checks that the
 * actor is the client the token was issued to, and Valet records the actor on every receipt.
 */
public class ValetGrantMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper {
    public static final String PROVIDER_ID = "valet-grant-mapper";
    public static final String CLAIM = "valet_grant";
    public static final String ACTOR_CLAIM = "act";
    private static final List<ProviderConfigProperty> CONFIG = new ArrayList<>();

    static {
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(CONFIG, ValetGrantMapper.class);
    }

    @Override public String getId() { return PROVIDER_ID; }
    @Override public String getDisplayCategory() { return TOKEN_MAPPER_CATEGORY; }
    @Override public String getDisplayType() { return "Veridact Valet: grant id"; }
    @Override public String getHelpText() { return "Adds the Valet grant id for this agent to its access tokens."; }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return CONFIG; }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel model, UserSessionModel userSession,
                            KeycloakSession session, ClientSessionContext clientSessionCtx) {
        String clientId = clientSessionCtx.getClientSession().getClient().getClientId();
        String grant = userSession.getNote(ValetConsentAuthenticator.grantNote(clientId));
        if (grant != null) {
            token.getOtherClaims().put(CLAIM, grant);
            Map<String, Object> actor = new LinkedHashMap<>();
            actor.put("sub", clientId);
            token.getOtherClaims().put(ACTOR_CLAIM, actor);
        }
    }
}
