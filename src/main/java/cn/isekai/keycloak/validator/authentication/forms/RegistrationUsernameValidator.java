package cn.isekai.keycloak.validator.authentication.forms;

import org.jboss.logging.Logger;
import javax.ws.rs.core.MultivaluedMap;
import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class RegistrationUsernameValidator implements FormAction, FormActionFactory {
    private static final Logger logger = Logger.getLogger(RegistrationUsernameValidator.class);

    private static final String INVALID_USERNAME = "usernameInvalid";
    private static final String FIELD_USERNAME = "username";
    private static final String PROVIDER_ID = "username-validator";
    private static final String FIELD_PATTERN = "pattern";

    @Override
    public String getHelpText() {
        return "valid username format";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(FIELD_PATTERN);
        property.setLabel("Username Pattern");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Pattern that allows use");
        CONFIG_PROPERTIES.add(property);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public void close() { }

    @Override
    public String getDisplayType() {
        return "Username Regex Validation";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED, AuthenticationExecutionModel.Requirement.DISABLED };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public FormAction create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) { }

    @Override
    public void postInit(KeycloakSessionFactory session) { }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void validate(ValidationContext context) {
        Map<String, String> config = context.getAuthenticatorConfig().getConfig();
        String pattern = config.get(FIELD_PATTERN);
        //logger.info("Username pattern: " + pattern);
        if (pattern == null) {
            context.success();
            return;
        }

        ArrayList<FormMessage> errors = new ArrayList<>();
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String username = formData.getFirst(FIELD_USERNAME);

        if (!Pattern.matches(pattern, username)) {
            errors.add(new FormMessage(FIELD_USERNAME, INVALID_USERNAME));
            context.error(INVALID_USERNAME);
            context.validationError(formData, errors);
            return;
        }

        context.success();
    }

    @Override
    public void success(FormContext context) {

    }

    @Override
    public void buildPage(FormContext context, LoginFormsProvider form) {

    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) { }
}
