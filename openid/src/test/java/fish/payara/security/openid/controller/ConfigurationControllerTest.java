/*
 * Copyright (c) 2024 Payara Foundation and/or its affiliates. All rights reserved.
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

import fish.payara.security.annotations.OpenIdAuthenticationDefinition;
import fish.payara.security.annotations.OpenIdProviderMetadata;
import fish.payara.security.openid.domain.OpenIdConfiguration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.el.ELProcessor;
import javax.json.JsonObject;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import static org.mockito.Mockito.when;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Test parsing configuration. Right now, only extraParameters are tested.
 *
 * @author Petr Aubrecht
 */
@ExtendWith(MockitoExtension.class)
@RunWith(JUnitPlatform.class)
public class ConfigurationControllerTest {

    private AutoCloseable closeable;

    @Mock
    private Config config;

    @Mock
    private ELProcessor elProcessor;

    @InjectMocks
    private ConfigurationController controller;

    @Mock
    private ProviderMetadataContoller providerMetadataContoller;

    @OpenIdAuthenticationDefinition(
            providerURI = "https://example.com/openid",
            providerMetadata = @OpenIdProviderMetadata(
                    issuer = "https://example.com/issuer",
                    jwksURI = "https://example.com/jwks",
                    authorizationEndpoint = "https://example.com/auth",
                    tokenEndpoint = "https://example.com/token",
                    responseTypesSupported = "code",
                    idTokenEncryptionAlgValuesSupported = "",
                    idTokenSigningAlgValuesSupported = ""
            ),
            clientId = "XYZ",
            extraParameters = {"a=1", "b=2", "c=3"}
    )
    public static class DefinitionExtraParametersStatic {
    }

    @OpenIdAuthenticationDefinition(
            providerURI = "https://example.com/openid",
            providerMetadata = @OpenIdProviderMetadata(
                    issuer = "https://example.com/issuer",
                    jwksURI = "https://example.com/jwks",
                    authorizationEndpoint = "https://example.com/auth",
                    tokenEndpoint = "https://example.com/token",
                    responseTypesSupported = "code",
                    idTokenEncryptionAlgValuesSupported = "",
                    idTokenSigningAlgValuesSupported = ""
            ),
            clientId = "XYZ",
            extraParameters = {"a=#{1}", "b=#{2}", "c=#{3}"}
    )
    public static class DefinitionExtraParametersValueExpression {
    }

    @OpenIdAuthenticationDefinition(
            providerURI = "https://example.com/openid",
            providerMetadata = @OpenIdProviderMetadata(
                    issuer = "https://example.com/issuer",
                    jwksURI = "https://example.com/jwks",
                    authorizationEndpoint = "https://example.com/auth",
                    tokenEndpoint = "https://example.com/token",
                    responseTypesSupported = "code",
                    idTokenEncryptionAlgValuesSupported = "",
                    idTokenSigningAlgValuesSupported = ""
            ),
            clientId = "XYZ",
            //securityBean.extraParametersArray returns array of strings in form of "a=1", "b=2", "c=3"
            extraParametersExpression = "#{securityBean.extraParametersArray}"
    )
    public static class DefinitionExtraParametersExpressionArray {
    }

    @OpenIdAuthenticationDefinition(
            providerURI = "https://example.com/openid",
            providerMetadata = @OpenIdProviderMetadata(
                    issuer = "https://example.com/issuer",
                    jwksURI = "https://example.com/jwks",
                    authorizationEndpoint = "https://example.com/auth",
                    tokenEndpoint = "https://example.com/token",
                    responseTypesSupported = "code",
                    idTokenEncryptionAlgValuesSupported = "",
                    idTokenSigningAlgValuesSupported = ""
            ),
            clientId = "XYZ",
            //securityBean.extraParametersString returns string in format "a=1,b=2,c=3"
            extraParametersExpression = "#{securityBean.extraParametersString}"
    )
    public static class DefinitionExtraParametersExpressionString {
    }

    @OpenIdAuthenticationDefinition(
            providerURI = "https://example.com/openid",
            providerMetadata = @OpenIdProviderMetadata(
                    issuer = "https://example.com/issuer",
                    jwksURI = "https://example.com/jwks",
                    authorizationEndpoint = "https://example.com/auth",
                    tokenEndpoint = "https://example.com/token",
                    responseTypesSupported = "code",
                    idTokenEncryptionAlgValuesSupported = "",
                    idTokenSigningAlgValuesSupported = ""
            ),
            clientId = "XYZ",
            // it will be overriden by MP, OpenIdAuthenticationDefinition.OPENID_MP_DISABLE_SCOPE_VALIDATION
            // format is URL parameters, e.g. a=1&b=2
            extraParameters = {"whatever"}
    )
    public static class DefinitionExtraParametersMPOverriden {
    }

    private static Map<String, List<String>> correctExtraParameters;

    @BeforeAll
    public static void initTests() {
        // When moving to Java 11, replace with this:
        // Map.of("a", List.of("1"), "b", List.of("2"), "c", List.of("3"));
        correctExtraParameters = new HashMap<>();
        correctExtraParameters.put("a", Arrays.asList("1"));
        correctExtraParameters.put("b", Arrays.asList("2"));
        correctExtraParameters.put("c", Arrays.asList("3"));
    }

    @BeforeEach
    public void openMocks() {
        closeable = MockitoAnnotations.openMocks(this);
    }

    @AfterEach
    public void releaseMocks() throws Exception {
        closeable.close();
    }


    public ConfigurationControllerTest() {
    }

    /**
     * Test buildConfig, static extra parameters.
     */
    @Test
    public void testBuildConfigExtraParametersStatic() {
        when(config.getOptionalValue(anyString(), eq(String.class))).thenReturn(Optional.empty());
        when(providerMetadataContoller.getDocument(anyString())).thenReturn(JsonObject.EMPTY_JSON_OBJECT);

        OpenIdAuthenticationDefinition definition = DefinitionExtraParametersStatic.class.getAnnotation(OpenIdAuthenticationDefinition.class);
        OpenIdConfiguration configuration = controller.buildConfig(definition, config, elProcessor);
        assertEquals(correctExtraParameters, configuration.getExtraParameters());
    }

    /**
     * Test buildConfig, extra parameters with expressions in values.
     */
    @Test
    public void testBuildConfigExtraParametersValueExpression() {
        when(config.getOptionalValue(anyString(), eq(String.class))).thenReturn(Optional.empty());
        when(providerMetadataContoller.getDocument(anyString())).thenReturn(JsonObject.EMPTY_JSON_OBJECT);
        when(elProcessor.getValue(eq("1"), any())).thenReturn("1");
        when(elProcessor.getValue(eq("2"), any())).thenReturn("2");
        when(elProcessor.getValue(eq("3"), any())).thenReturn("3");

        OpenIdAuthenticationDefinition definition = DefinitionExtraParametersValueExpression.class.getAnnotation(OpenIdAuthenticationDefinition.class);
        OpenIdConfiguration configuration = controller.buildConfig(definition, config, elProcessor);
        assertEquals(correctExtraParameters, configuration.getExtraParameters());
    }

    /**
     * Test buildConfig, extra parameters using expression, which returns list
     * of strings.
     */
    @Test
    public void testBuildConfigExtraParametersExpressionArray() {
        when(config.getOptionalValue(anyString(), eq(String.class))).thenReturn(Optional.empty());
        when(providerMetadataContoller.getDocument(anyString())).thenReturn(JsonObject.EMPTY_JSON_OBJECT);
        when(elProcessor.getValue(any(), any())).thenReturn(null);
        when(elProcessor.getValue(eq("securityBean.extraParametersArray"), any())).thenReturn(new String[]{"a=1", "b=2", "c=3"});
        // Testing Mockito
        assertArrayEquals(new String[]{"a=1", "b=2", "c=3"}, (String[]) elProcessor.getValue("securityBean.extraParametersArray", String.class));

        OpenIdAuthenticationDefinition definition = DefinitionExtraParametersExpressionArray.class.getAnnotation(OpenIdAuthenticationDefinition.class);
        OpenIdConfiguration configuration = controller.buildConfig(definition, config, elProcessor);
        assertEquals(correctExtraParameters, configuration.getExtraParameters());
    }

    /**
     * Test buildConfig, extra parameters using expression, which returns
     * strings with comma-separated values.
     */
    @Test
    public void testBuildConfigExtraParametersExpressionString() {
        when(config.getOptionalValue(anyString(), eq(String.class))).thenReturn(Optional.empty());
        when(providerMetadataContoller.getDocument(anyString())).thenReturn(JsonObject.EMPTY_JSON_OBJECT);
        when(elProcessor.getValue(eq("securityBean.extraParametersString"), any())).thenReturn("a=1,b=2,c=3");

        OpenIdAuthenticationDefinition definition = DefinitionExtraParametersExpressionString.class.getAnnotation(OpenIdAuthenticationDefinition.class);
        OpenIdConfiguration configuration = controller.buildConfig(definition, config, elProcessor);
        assertEquals(correctExtraParameters, configuration.getExtraParameters());
    }

    /**
     * Test buildConfig, extra parameters using MPConfig,
     * OpenIdAuthenticationDefinition.OPENID_MP_DISABLE_SCOPE_VALIDATION
     */
    @Test
    public void testBuildConfigExtraParametersViaMPConfig() {
        when(config.getOptionalValue(anyString(), any())).thenReturn(Optional.empty());
        when(providerMetadataContoller.getDocument(anyString())).thenReturn(JsonObject.EMPTY_JSON_OBJECT);
        //when(elProcessor.getValue(any(), any())).thenReturn(null);
        when(config.getOptionalValue(eq(OpenIdAuthenticationDefinition.OPENID_MP_EXTRA_PARAMS_RAW), eq(String.class))).thenReturn(Optional.of("a=1&b=2&c=3"));

        OpenIdAuthenticationDefinition definition = DefinitionExtraParametersMPOverriden.class.getAnnotation(OpenIdAuthenticationDefinition.class);
        OpenIdConfiguration configuration = controller.buildConfig(definition, config, elProcessor);
        assertEquals(correctExtraParameters, configuration.getExtraParameters());
    }

    /**
     * Test of createUrlQuery method, of class ConfigurationController.
     */
    @Test
    public void testCreateUrlQuery() {
        String[] extraParameters = new String[]{"a=1", "b=2"};
        String urlParams = ConfigurationController.createUrlQuery(elProcessor, "extraParameters", extraParameters);
        assertEquals("a=1&b=2", urlParams);
    }
}
