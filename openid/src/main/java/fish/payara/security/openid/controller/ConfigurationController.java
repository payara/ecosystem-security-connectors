/*
 * Copyright (c) [2020-2021] Payara Foundation and/or its affiliates. All rights reserved.
 *
 *  The contents of this file are subject to the terms of either the GNU
 *  General Public License Version 2 only ("GPL") or the Common Development
 *  and Distribution License("CDDL") (collectively, the "License").  You
 *  may not use this file except in compliance with the License.  You can
 *  obtain a copy of the License at
 *  https://github.com/payara/Payara/blob/master/LICENSE.txt
 *  See the License for the specific
 *  language governing permissions and limitations under the License.
 *
 *  When distributing the software, include this License Header Notice in each
 *  file and include the License file at glassfish/legal/LICENSE.txt.
 *
 *  GPL Classpath Exception:
 *  The Payara Foundation designates this particular file as subject to the "Classpath"
 *  exception as provided by the Payara Foundation in the GPL Version 2 section of the License
 *  file that accompanied this code.
 *
 *  Modifications:
 *  If applicable, add the following below the License Header, with the fields
 *  enclosed by brackets [] replaced by your own identifying information:
 *  "Portions Copyright [year] [name of copyright owner]"
 *
 *  Contributor(s):
 *  If you wish your version of this file to be governed by only the CDDL or
 *  only the GPL Version 2, indicate your decision by adding "[Contributor]
 *  elects to include this software in this distribution under the [CDDL or GPL
 *  Version 2] license."  If you don't indicate a single choice of license, a
 *  recipient has the option to distribute your version of this file under
 *  either the CDDL, the GPL Version 2 or to extend the choice of license to
 *  its licensees as provided above.  However, if you add GPL Version 2 code
 *  and therefore, elected the GPL Version 2 license, then the option applies
 *  only if the new code is made subject to such option by the copyright
 *  holder.
 */
package fish.payara.security.openid.controller;

import fish.payara.security.annotations.ClaimsDefinition;
import fish.payara.security.annotations.LogoutDefinition;
import fish.payara.security.annotations.OpenIdAuthenticationDefinition;
import fish.payara.security.annotations.OpenIdProviderMetadata;
import fish.payara.security.openid.OpenIdAuthenticationException;
import fish.payara.security.openid.OpenIdUtil;
import fish.payara.security.openid.api.ClientAuthenticationMethod;
import fish.payara.security.openid.api.OpenIdConstant;
import fish.payara.security.openid.api.PromptType;
import fish.payara.security.openid.domain.ClaimsConfiguration;
import fish.payara.security.openid.domain.LogoutConfiguration;
import fish.payara.security.openid.domain.OpenIdConfiguration;
import fish.payara.security.openid.domain.OpenIdTokenEncryptionMetadata;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import javax.json.JsonObject;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static java.util.stream.Collectors.joining;

/**
 * Build and validate the OpenId Connect client configuration
 *
 * @author Gaurav Gupta
 */
@ApplicationScoped
public class ConfigurationController implements Serializable {

    @Inject
    private ProviderMetadataContoller providerMetadataContoller;

    private static final String SPACE_SEPARATOR = " ";

    private volatile transient LastBuiltConfig lastBuiltConfig;

    @Produces
    @RequestScoped
    public OpenIdConfiguration produceConfiguration(OpenIdAuthenticationDefinition definition) {
        if (lastBuiltConfig == null) {
            lastBuiltConfig = new LastBuiltConfig(null, null);
        }
        OpenIdConfiguration cached = lastBuiltConfig.cachedConfiguration(definition);
        if (cached != null) {
            return cached;
        }
        OpenIdConfiguration config = buildConfig(definition);
        lastBuiltConfig = new LastBuiltConfig(definition, config);
        return config;
    }

    /**
     * Creates the {@link OpenIdConfiguration} using the properties as defined
     * in an {@link OpenIdAuthenticationDefinition} annotation or using MP
     * Config source. MP Config source value take precedence over
     * {@link OpenIdAuthenticationDefinition} annotation value.
     *
     * @param definition
     * @return
     */
    public OpenIdConfiguration buildConfig(OpenIdAuthenticationDefinition definition) {
        Config provider = ConfigProvider.getConfig();

        String providerURI;
        JsonObject providerDocument;
        String issuerURI;
        String authorizationEndpoint;
        String tokenEndpoint;
        String userinfoEndpoint;
        String endSessionEndpoint;
        String jwksURI;
        URL jwksURL;
        Set<String> scopesSupported;
        Set<String> responseTypesSupported;
        Set<String> subjectTypesSupported;
        Set<String> idTokenSigningAlgValuesSupported;
        Set<String> idTokenEncryptionAlgValuesSupported;
        Set<String> idTokenEncryptionEncValuesSupported;
        Set<String> claimsSupported;

        providerURI = OpenIdUtil.getConfiguredValue(String.class, definition.providerURI(), provider, OpenIdAuthenticationDefinition.OPENID_MP_PROVIDER_URI);
        fish.payara.security.annotations.OpenIdProviderMetadata providerMetadata = definition.providerMetadata();
        providerDocument = providerMetadataContoller.getDocument(providerURI);

        // collect metadata either from the metadata annotation or from the autoconfiguration providerDocument
        issuerURI = OpenIdUtil.readConfiguredValueFromMetadataOrProvider(providerMetadata.issuer(), providerDocument, OpenIdConstant.ISSUER, provider, OpenIdProviderMetadata.OPENID_MP_ISSUER);

        if (issuerURI == null || issuerURI.isEmpty()) {
            throw new OpenIdAuthenticationException("issuer URL is not available, specify it either in @OpenIdProviderMetadata or by providerURI and autoconfiguration");
        }

        authorizationEndpoint = OpenIdUtil.readConfiguredValueFromMetadataOrProvider(providerMetadata.authorizationEndpoint(), providerDocument, OpenIdConstant.AUTHORIZATION_ENDPOINT, provider, OpenIdProviderMetadata.OPENID_MP_AUTHORIZATION_ENDPOINT);
        tokenEndpoint = OpenIdUtil.readConfiguredValueFromMetadataOrProvider(providerMetadata.tokenEndpoint(), providerDocument, OpenIdConstant.TOKEN_ENDPOINT, provider, OpenIdProviderMetadata.OPENID_MP_TOKEN_ENDPOINT);
        userinfoEndpoint = OpenIdUtil.readConfiguredValueFromMetadataOrProvider(providerMetadata.userinfoEndpoint(), providerDocument, OpenIdConstant.USERINFO_ENDPOINT, provider, OpenIdProviderMetadata.OPENID_MP_USERINFO_ENDPOINT);
        endSessionEndpoint = OpenIdUtil.readConfiguredValueFromMetadataOrProvider(providerMetadata.endSessionEndpoint(), providerDocument, OpenIdConstant.END_SESSION_ENDPOINT, provider, OpenIdProviderMetadata.OPENID_MP_END_SESSION_ENDPOINT);
        jwksURI = OpenIdUtil.readConfiguredValueFromMetadataOrProvider(providerMetadata.jwksURI(), providerDocument, OpenIdConstant.JWKS_URI, provider, OpenIdProviderMetadata.OPENID_MP_JWKS_URI);
        try {
            jwksURL = new URL(jwksURI);
        } catch (MalformedURLException ex) {
            throw new OpenIdAuthenticationException("jwksURI is not a valid URL: " + jwksURI, ex);
        }
        scopesSupported = OpenIdUtil.readConfiguredValueFromMetadataOrProvider(providerMetadata.scopesSupported(), providerDocument, OpenIdConstant.SCOPES_SUPPORTED, provider, OpenIdProviderMetadata.OPENID_MP_SCOPES_SUPPORTED);
        responseTypesSupported = OpenIdUtil.readConfiguredValueFromMetadataOrProvider(providerMetadata.responseTypesSupported(), providerDocument, OpenIdConstant.RESPONSE_TYPES_SUPPORTED, provider, OpenIdProviderMetadata.OPENID_MP_RESPONSE_TYPES_SUPPORTED);
        subjectTypesSupported = OpenIdUtil.readConfiguredValueFromMetadataOrProvider(providerMetadata.subjectTypesSupported(), providerDocument, OpenIdConstant.SUBJECT_TYPES_SUPPORTED, provider, OpenIdProviderMetadata.OPENID_MP_SUBJECT_TYPES_SUPPORTED);
        idTokenSigningAlgValuesSupported = OpenIdUtil.readConfiguredValueFromMetadataOrProvider(providerMetadata.idTokenSigningAlgValuesSupported(), providerDocument, OpenIdConstant.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED, provider, OpenIdProviderMetadata.OPENID_MP_ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED);
        idTokenEncryptionAlgValuesSupported = OpenIdUtil.readConfiguredValueFromMetadataOrProvider(providerMetadata.idTokenEncryptionAlgValuesSupported(), providerDocument, OpenIdConstant.ID_TOKEN_ENCRYPTION_ALG_VALUES_SUPPORTED, provider, OpenIdProviderMetadata.OPENID_MP_ID_TOKEN_ENCRYPTION_ALG_VALUES_SUPPORTED);
        idTokenEncryptionEncValuesSupported = OpenIdUtil.readConfiguredValueFromMetadataOrProvider(providerMetadata.idTokenEncryptionEncValuesSupported(), providerDocument, OpenIdConstant.ID_TOKEN_ENCRYPTION_ENC_VALUES_SUPPORTED, provider, OpenIdProviderMetadata.OPENID_MP_ID_TOKEN_ENCRYPTION_ENC_VALUES_SUPPORTED);
        claimsSupported = OpenIdUtil.readConfiguredValueFromMetadataOrProvider(providerMetadata.claimsSupported(), providerDocument, OpenIdConstant.CLAIMS_SUPPORTED, provider, OpenIdProviderMetadata.OPENID_MP_CLAIMS_SUPPORTED);

        String clientId = OpenIdUtil.getConfiguredValue(String.class, definition.clientId(), provider, OpenIdAuthenticationDefinition.OPENID_MP_CLIENT_ID);
        char[] clientSecret = OpenIdUtil.getConfiguredValue(String.class, definition.clientSecret(), provider, OpenIdAuthenticationDefinition.OPENID_MP_CLIENT_SECRET).toCharArray();
        String redirectURI = OpenIdUtil.getConfiguredValue(String.class, definition.redirectURI(), provider, OpenIdAuthenticationDefinition.OPENID_MP_REDIRECT_URI);

        String scopes = Arrays.stream(definition.scope()).collect(joining(SPACE_SEPARATOR));
        scopes = OpenIdUtil.getConfiguredValue(String.class, scopes, provider, OpenIdAuthenticationDefinition.OPENID_MP_SCOPE);
        if (OpenIdUtil.isEmpty(scopes)) {
            scopes = OpenIdConstant.OPENID_SCOPE;
        } else if (!scopes.contains(OpenIdConstant.OPENID_SCOPE)) {
            scopes = OpenIdConstant.OPENID_SCOPE + SPACE_SEPARATOR + scopes;
        }

        String responseType = OpenIdUtil.getConfiguredValue(String.class, definition.responseType(), provider, OpenIdAuthenticationDefinition.OPENID_MP_RESPONSE_TYPE);
        responseType
                = Arrays.stream(responseType.trim().split(SPACE_SEPARATOR))
                .map(String::toLowerCase)
                .sorted()
                .collect(joining(SPACE_SEPARATOR));

        String responseMode = OpenIdUtil.getConfiguredValue(String.class, definition.responseMode(), provider, OpenIdAuthenticationDefinition.OPENID_MP_RESPONSE_MODE);

        String display = definition.display().toString().toLowerCase();
        display = OpenIdUtil.getConfiguredValue(String.class, display, provider, OpenIdAuthenticationDefinition.OPENID_MP_DISPLAY);

        String prompt = Arrays.stream(definition.prompt())
                .map(PromptType::toString)
                .map(String::toLowerCase)
                .collect(joining(SPACE_SEPARATOR));
        prompt = OpenIdUtil.getConfiguredValue(String.class, prompt, provider, OpenIdAuthenticationDefinition.OPENID_MP_PROMPT);

        String extraParametersFromAnnotation = createUrlQuery("extraParameters", definition.extraParameters());

        boolean useNonce = OpenIdUtil.getConfiguredValue(Boolean.class, definition.useNonce(), provider, OpenIdAuthenticationDefinition.OPENID_MP_USE_NONCE);
        boolean useSession = OpenIdUtil.getConfiguredValue(Boolean.class, definition.useSession(), provider, OpenIdAuthenticationDefinition.OPENID_MP_USE_SESSION);

        int jwksConnectTimeout = OpenIdUtil.getConfiguredValue(Integer.class, definition.jwksConnectTimeout(), provider, OpenIdAuthenticationDefinition.OPENID_MP_JWKS_CONNECT_TIMEOUT);
        int jwksReadTimeout = OpenIdUtil.getConfiguredValue(Integer.class, definition.jwksReadTimeout(), provider, OpenIdAuthenticationDefinition.OPENID_MP_JWKS_READ_TIMEOUT);

        String encryptionAlgorithm = provider.getOptionalValue(OpenIdAuthenticationDefinition.OPENID_MP_CLIENT_ENC_ALGORITHM, String.class).orElse(null);
        String encryptionMethod = provider.getOptionalValue(OpenIdAuthenticationDefinition.OPENID_MP_CLIENT_ENC_METHOD, String.class).orElse(null);
        String privateKeyJWKS = provider.getOptionalValue(OpenIdAuthenticationDefinition.OPENID_MP_CLIENT_ENC_JWKS, String.class).orElse(null);

        String callerNameClaim = OpenIdUtil.getConfiguredValue(String.class, definition.claimsDefinition().callerNameClaim(), provider, ClaimsDefinition.OPENID_MP_CALLER_NAME_CLAIM);
        String callerGroupsClaim = OpenIdUtil.getConfiguredValue(String.class, definition.claimsDefinition().callerGroupsClaim(), provider, ClaimsDefinition.OPENID_MP_CALLER_GROUP_CLAIM);

        Boolean notifyProvider = OpenIdUtil.getConfiguredValue(Boolean.class, definition.logout().notifyProvider(), provider, LogoutDefinition.OPENID_MP_PROVIDER_NOTIFY_LOGOUT);
        String logoutRedirectURI = OpenIdUtil.getConfiguredValue(String.class, definition.logout().redirectURI(), provider, LogoutDefinition.OPENID_MP_POST_LOGOUT_REDIRECT_URI);
        Boolean accessTokenExpiry = OpenIdUtil.getConfiguredValue(Boolean.class, definition.logout().accessTokenExpiry(), provider, LogoutDefinition.OPENID_MP_LOGOUT_ON_ACCESS_TOKEN_EXPIRY);
        Boolean identityTokenExpiry = OpenIdUtil.getConfiguredValue(Boolean.class, definition.logout().identityTokenExpiry(), provider, LogoutDefinition.OPENID_MP_LOGOUT_ON_IDENTITY_TOKEN_EXPIRY);

        boolean tokenAutoRefresh = OpenIdUtil.getConfiguredValue(Boolean.class, definition.tokenAutoRefresh(), provider, OpenIdAuthenticationDefinition.OPENID_MP_TOKEN_AUTO_REFRESH);
        int tokenMinValidity = OpenIdUtil.getConfiguredValue(Integer.class, definition.tokenMinValidity(), provider, OpenIdAuthenticationDefinition.OPENID_MP_TOKEN_MIN_VALIDITY);
        boolean userClaimsFromIDToken = OpenIdUtil.getConfiguredValue(Boolean.class, definition.userClaimsFromIDToken(), provider, OpenIdAuthenticationDefinition.OPENID_MP_USER_CLAIMS_FROM_ID_TOKEN);
        String extraParamsRaw = OpenIdUtil.getConfiguredValue(String.class, extraParametersFromAnnotation, provider, OpenIdAuthenticationDefinition.OPENID_MP_EXTRA_PARAMS_RAW);
        Map<String, List<String>> extraParameters = parseMultiMapFromUrlQuery(extraParamsRaw);
        boolean disableScopeValidation = OpenIdUtil.getConfiguredValue(Boolean.class, false, provider, OpenIdAuthenticationDefinition.OPENID_MP_DISABLE_SCOPE_VALIDATION);

        // Get the client authentication method
        final String clientAuthenticationMethodProvided = OpenIdUtil.getConfiguredValue(String.class,
                definition.clientAuthentication().toString().toLowerCase(), provider,
                OpenIdAuthenticationDefinition.OPENID_MP_CLIENT_AUTHENTICATION);

        // Convert string value into an enum
        final ClientAuthenticationMethod clientAuthenticationMethod =
                ClientAuthenticationMethod.fromName(clientAuthenticationMethodProvided);

        final ClientAuthentication clientAuthentication;
        if (clientAuthenticationMethod == ClientAuthenticationMethod.CLIENT_SECRET_BASIC) {
            clientAuthentication = new ClientSecretBasic(clientId, clientSecret);
        } else if (clientAuthenticationMethod == ClientAuthenticationMethod.CLIENT_SECRET_POST) {
            clientAuthentication = new ClientSecretPost(clientId, clientSecret);
        } else {
            // Client authentication method is not defined or not supported by Payara OpenID implementation.
            // Make it fail during validation of client configuration.
            clientAuthentication = new NotSupportedClientAuthentication(clientAuthenticationMethodProvided);
        }


        fish.payara.security.openid.domain.OpenIdProviderMetadata openIdProviderMetadata = new fish.payara.security.openid.domain.OpenIdProviderMetadata(
                providerDocument,
                issuerURI,
                scopesSupported,
                claimsSupported,
                responseTypesSupported,
                idTokenSigningAlgValuesSupported,
                idTokenEncryptionAlgValuesSupported,
                idTokenEncryptionEncValuesSupported,
                subjectTypesSupported)
                .setAuthorizationEndpoint(authorizationEndpoint)
                .setTokenEndpoint(tokenEndpoint)
                .setUserinfoEndpoint(userinfoEndpoint)
                .setEndSessionEndpoint(endSessionEndpoint)
                .setJwksURL(jwksURL);

        OpenIdConfiguration configuration = new OpenIdConfiguration()
                .setProviderMetadata(
                        openIdProviderMetadata
                )
                .setClaimsConfiguration(
                        new ClaimsConfiguration()
                                .setCallerNameClaim(callerNameClaim)
                                .setCallerGroupsClaim(callerGroupsClaim)
                ).setLogoutConfiguration(
                        new LogoutConfiguration()
                                .setNotifyProvider(notifyProvider)
                                .setRedirectURI(logoutRedirectURI)
                                .setAccessTokenExpiry(accessTokenExpiry)
                                .setIdentityTokenExpiry(identityTokenExpiry)
                )
                .setEncryptionMetadata(
                        new OpenIdTokenEncryptionMetadata()
                                .setEncryptionAlgorithm(encryptionAlgorithm)
                                .setEncryptionMethod(encryptionMethod)
                                .setPrivateKeySource(privateKeyJWKS)
                )
                .setClientId(clientId)
                .setClientSecret(clientSecret)
                .setRedirectURI(redirectURI)
                .setScopes(scopes)
                .setResponseType(responseType)
                .setResponseMode(responseMode)
                .setExtraParameters(extraParameters)
                .setPrompt(prompt)
                .setDisplay(display)
                .setUseNonce(useNonce)
                .setUseSession(useSession)
                .setJwksConnectTimeout(jwksConnectTimeout)
                .setJwksReadTimeout(jwksReadTimeout)
                .setTokenAutoRefresh(tokenAutoRefresh)
                .setTokenMinValidity(tokenMinValidity)
                .setUserClaimsFromIDToken(userClaimsFromIDToken)
                .setDisableScopeValidation(disableScopeValidation)
                .setClientAuthentication(clientAuthentication);

        validateConfiguration(configuration);

        return configuration;
    }

    /**
     * Validate the properties of the OpenId Connect Client and Provider
     * Metadata
     */
    private void validateConfiguration(OpenIdConfiguration configuration) {
        List<String> errorMessages = new ArrayList<>();
        errorMessages.addAll(validateProviderMetadata(configuration));
        errorMessages.addAll(validateClientConfiguration(configuration));

        if (!errorMessages.isEmpty()) {
            throw new OpenIdAuthenticationException(errorMessages.toString());
        }
    }

    private List<String> validateProviderMetadata(OpenIdConfiguration configuration) {
        List<String> errorMessages = new ArrayList<>();
        String issuerURI = configuration.getProviderMetadata().getIssuerURI();

        if (OpenIdUtil.isEmpty(issuerURI)) {
            errorMessages.add("issuer metadata is mandatory");
        }
        try {
            // only try to parse issuerURI
            new URL(issuerURI);
        } catch (MalformedURLException ex) {
            errorMessages.add("issuer metadata is not a valid URL: " + ex.getMessage());
        }

        if (OpenIdUtil.isEmpty(configuration.getProviderMetadata().getAuthorizationEndpoint())) {
            errorMessages.add("authorization_endpoint metadata is mandatory");
        }
        if (OpenIdUtil.isEmpty(configuration.getProviderMetadata().getTokenEndpoint())) {
            errorMessages.add("token_endpoint metadata is mandatory");
        }
        if (configuration.getProviderMetadata().getJwksURL() == null) {
            errorMessages.add("jwks_uri metadata is mandatory");
        }
        if (configuration.getProviderMetadata().getResponseTypesSupported().isEmpty()) {
            errorMessages.add("response_types_supported metadata is mandatory");
        }
        if (configuration.getProviderMetadata().getIdTokenSigningAlgValuesSupported().isEmpty()) {
            errorMessages.add("id_token_signing_alg_values_supported metadata is mandatory");
        }
        return errorMessages;
    }

    private List<String> validateClientConfiguration(OpenIdConfiguration configuration) {
        List<String> errorMessages = new ArrayList<>();

        if (OpenIdUtil.isEmpty(configuration.getClientId())) {
            errorMessages.add("client_id request parameter is mandatory");
        }
        if (OpenIdUtil.isEmpty(configuration.getRedirectURI())) {
            errorMessages.add("redirect_uri request parameter is mandatory");
        }
        if (configuration.getJwksConnectTimeout() <= 0) {
            errorMessages.add("jwksConnectTimeout value is not valid");
        }
        if (configuration.getJwksReadTimeout() <= 0) {
            errorMessages.add("jwksReadTimeout value is not valid");
        }

        if (OpenIdUtil.isEmpty(configuration.getResponseType())) {
            errorMessages.add("The response type must contain at least one value");
        } else if (!configuration.getProviderMetadata().getResponseTypesSupported().contains(configuration.getResponseType())
                && !OpenIdConstant.AUTHORIZATION_CODE_FLOW_TYPES.contains(configuration.getResponseType())
                && !OpenIdConstant.IMPLICIT_FLOW_TYPES.contains(configuration.getResponseType())
                && !OpenIdConstant.HYBRID_FLOW_TYPES.contains(configuration.getResponseType())) {
            errorMessages.add("Unsupported OpenID Connect response type value : " + configuration.getResponseType());
        }

        if(!configuration.isDisableScopeValidation()) {
            Set<String> supportedScopes = configuration.getProviderMetadata().getScopesSupported();
            if (!supportedScopes.isEmpty()) {
                for (String scope : configuration.getScopes().split(SPACE_SEPARATOR)) {
                    if (!supportedScopes.contains(scope)) {
                        errorMessages.add(String.format(
                                "%s scope is not supported by %s OpenId Connect provider",
                                scope,
                                configuration.getProviderMetadata().getIssuerURI())
                        );
                    }
                }
            }
        }

        if (configuration.getClientAuthentication().getAuthenticationMethod() == null) {
            errorMessages.add(String.format("client_authentication_method value is not valid: %s",
                    configuration.getClientAuthentication()));
        }

        return errorMessages;
    }

    /**
     * Create Url query from pairs of parameters.
     */
    public static String createUrlQuery(String paramsName, String[] parameters) {
        StringBuilder extraParametersFromAnnotationBuf = new StringBuilder();
        String extraParamDelim = "";
        for (String extraParameter : parameters) {
            String[] parts = extraParameter.split("=");
            if (parts.length == 0 || parts[0].length() == 0) {
                throw new OpenIdAuthenticationException(paramsName + " contain parameter without key: '" + extraParameter + "', expected format: key=value");
            }
            String key = parts[0];
            String value = parts.length > 1 ? parts[1] : null;
            extraParametersFromAnnotationBuf.append(extraParamDelim)
                    .append(URLEncoder.encode(key, StandardCharsets.UTF_8));
            if (value != null) {
                extraParametersFromAnnotationBuf
                        .append("=")
                        .append(URLEncoder.encode(value, StandardCharsets.UTF_8));
            }
            extraParamDelim = "&";
        }
        return extraParametersFromAnnotationBuf.toString();
    }

    /**
     * Parse Url query format to multimap.
     */
    public static Map<String, List<String>> parseMultiMapFromUrlQuery(String query) {
        Map<String, List<String>> multiMap = new LinkedHashMap<>();
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            String[] keyValue = pair.split("=");
            String key = keyValue[0];
            String value = keyValue.length > 1 ? URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8) : null;
            List<String> values = multiMap.computeIfAbsent(key, k -> new ArrayList<>());
            values.add(value);
        }
        return multiMap;
    }

    static class LastBuiltConfig {
        private final OpenIdAuthenticationDefinition definition;
        private final OpenIdConfiguration configuration;

        public LastBuiltConfig(OpenIdAuthenticationDefinition definition, OpenIdConfiguration configuration) {
            this.definition = definition;
            this.configuration = configuration;
        }

        OpenIdConfiguration cachedConfiguration(OpenIdAuthenticationDefinition definition) {
            if (this.definition != null && this.definition.equals(definition)) {
                return configuration;
            }
            return null;
        }
    }

    /**
     * Behavior-relevant attributes of a definition as a key for configuration cache.
     * This can serve as a key to a cache of OpenIdConfiguration objects if configuration varies among requests, which
     * is a feature coming soon.
     */
    static CacheKey keyFromDefinition(OpenIdAuthenticationDefinition definition) {
        String[][] values = {
                {
                        definition.providerURI(),
                        definition.clientId(),
                        definition.clientSecret(),
                        definition.redirectURI(),
                        definition.responseType(),
                        definition.responseMode(),
                        Arrays.toString(definition.prompt()),
                        String.valueOf(definition.useNonce()),
                        String.valueOf(definition.useSession()),
                        String.valueOf(definition.tokenAutoRefresh()),
                        String.valueOf(definition.tokenMinValidity())
                },
                definition.scope(),
                definition.extraParameters(),
                providerMetadataAttrs(definition.providerMetadata()),
                claimsAttrs(definition.claimsDefinition()),
                logoutAttrs(definition.logout())
        };

        // and now concatentate all of these together to form a key
        return new CacheKey(Stream.of(values).flatMap(Stream::of).toArray(String[]::new));
    }

    private static String[] logoutAttrs(LogoutDefinition logout) {
        return logout != null ? new String[]{
                String.valueOf(logout.notifyProvider()),
                logout.redirectURI(),
                String.valueOf(logout.accessTokenExpiry()),
                String.valueOf(logout.identityTokenExpiry())
        } : new String[4];
    }

    private static String[] claimsAttrs(ClaimsDefinition claimsDefinition) {
        return claimsDefinition != null ? new String[]{
                claimsDefinition.callerGroupsClaim(),
                claimsDefinition.callerNameClaim()
        } : new String[2];
    }

    private static String[] providerMetadataAttrs(OpenIdProviderMetadata providerMetadata) {
        return providerMetadata != null ? new String[]{
                providerMetadata.authorizationEndpoint(),
                providerMetadata.tokenEndpoint(),
                providerMetadata.userinfoEndpoint(),
                providerMetadata.endSessionEndpoint(),
                providerMetadata.jwksURI(),
        } : new String[5];
    }

}
