package net.veridact.valet.keycloak;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class ValetConsentAuthenticatorFactory implements AuthenticatorFactory {
    public static final String PROVIDER_ID = "valet-consent";
    private static final ValetConsentAuthenticator SINGLETON = new ValetConsentAuthenticator();

    private static final List<ProviderConfigProperty> CONFIG = List.of(
            prop(ValetSettings.CONSENT_URL, "Valet consent URL", "Where Valet's consent hand-off page lives, e.g. https://valet.bank.example/handoff/consent", ProviderConfigProperty.STRING_TYPE),
            prop(ValetSettings.ISSUER, "Valet issuer", "Valet's issuer URL (the audience of the ticket, the issuer of the result)", ProviderConfigProperty.STRING_TYPE),
            prop(ValetSettings.SECRET, "Hand-off secret", "Shared secret, 32+ characters (PoC; use asymmetric keys in production)", ProviderConfigProperty.PASSWORD));

    private static ProviderConfigProperty prop(String name, String label, String help, String type) {
        ProviderConfigProperty p = new ProviderConfigProperty();
        p.setName(name);
        p.setLabel(label);
        p.setHelpText(help);
        p.setType(type);
        if (ProviderConfigProperty.PASSWORD.equals(type)) p.setSecret(true);
        return p;
    }

    @Override public String getId() { return PROVIDER_ID; }
    @Override public String getDisplayType() { return "Veridact Valet: AI agent consent"; }
    @Override public String getReferenceCategory() { return "valet-consent"; }
    @Override public boolean isConfigurable() { return true; }
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[]{AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.DISABLED};
    }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public String getHelpText() {
        return "For AI agent clients (attribute valet.agent=true): sends the signed-in customer to Valet's consent screen and records the grant.";
    }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return CONFIG; }
    @Override public Authenticator create(KeycloakSession session) { return SINGLETON; }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
}
