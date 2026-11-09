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
import java.util.List;

/**
 * Puts the Valet grant id (recorded by ValetConsentAuthenticator) in the agent's access token as "valet_grant".
 * Refreshed tokens carry it too, because it lives in the user session. Valet's enforcement looks the grant up on
 * every call, so pause, revoke and limits apply to Keycloak's tokens exactly as to Valet's own.
 */
public class ValetGrantMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper {
    public static final String PROVIDER_ID = "valet-grant-mapper";
    public static final String CLAIM = "valet_grant";
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
        }
    }
}
