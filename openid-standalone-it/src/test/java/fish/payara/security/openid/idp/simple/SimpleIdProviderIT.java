/*
 *
 *  DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 *  Copyright (c) 2022 Payara Foundation and/or its affiliates. All rights reserved.
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
 *
 */

package fish.payara.security.openid.idp.simple;

import java.io.IOException;
import java.net.URI;
import java.text.ParseException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.json.JsonObject;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import fish.payara.security.openid.idp.LogExceptionOnServerSide;
import fish.payara.security.openid.idp.OpenIdDeployment;
import org.glassfish.jersey.logging.LoggingFeature;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit5.ArquillianExtension;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;

import static fish.payara.security.connectors.openid.api.OpenIdConstant.CLIENT_ID;
import static fish.payara.security.connectors.openid.api.OpenIdConstant.CODE;
import static fish.payara.security.connectors.openid.api.OpenIdConstant.GRANT_TYPE;
import static fish.payara.security.connectors.openid.api.OpenIdConstant.NONCE;
import static fish.payara.security.connectors.openid.api.OpenIdConstant.REDIRECT_URI;
import static fish.payara.security.connectors.openid.api.OpenIdConstant.RESPONSE_TYPE;
import static fish.payara.security.connectors.openid.api.OpenIdConstant.SCOPE;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Validates that AbstractIdProvider behaves as expected for the simplest case without actually using connector.
 */
@ExtendWith(ArquillianExtension.class)
@ExtendWith(LogExceptionOnServerSide.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class SimpleIdProviderIT {
    @Deployment
    public static WebArchive deployment() {
        return OpenIdDeployment.withAbstractProvider(ShrinkWrap.create(WebArchive.class))
                .addClasses(SimpleIdProvider.class, Callback.class).addClass(JaxrsApplication.class);
    }

    @ArquillianResource
    URI baseUri;

    private static final Logger LOGGER = Logger.getLogger(SimpleIdProviderIT.class.getName());

    private JsonObject config;

    @BeforeEach
    public void fetchConfig() {
        // Before/After All is executed on client side, but these are executed server-side
        if (config != null) {
            return;
        }
        WebTarget target = ClientBuilder.newClient().target(baseUri).path("simple/.well-known/openid-configuration");
        LOGGER.info("Will request " + target.getUri());
        config = target.request(MediaType.APPLICATION_JSON).get(JsonObject.class);
    }

    @Test
    public void deploys() {
        assertNotNull(config);
        LOGGER.info(config.toString());
    }

    @Test
    public void endpointUrisAreAbsolute() {
        assertTrue(config.getString("authorization_endpoint").startsWith("http"));
        assertTrue(config.getString("token_endpoint").startsWith("http"));
    }

    @Test
    public void codeExchangeFlowWorks() throws ParseException, IOException, JOSEException {
        Client client = ClientBuilder.newClient().register(new LoggingFeature(LOGGER,
                Level.INFO, LoggingFeature.Verbosity.PAYLOAD_ANY, 10000));
        String nonce = "123098";
        // the relying party sends client to idp authorization endpoint
        String code = client.target(config.getString("authorization_endpoint"))
                .queryParam(CLIENT_ID, SimpleIdProvider.CLIENT_ID)
                .queryParam(REDIRECT_URI, baseUri.resolve("callback/code"))
                .queryParam(NONCE, nonce)
                .queryParam(RESPONSE_TYPE, "code")
                .queryParam(SCOPE, "openid")
                .request().get(String.class);
        // idp redirects to callback endpoint of relying party
        assertNotNull(code, "Code should be returned as response to authorization request");
        // relaying party obtains the tokens
        Form tokenRequest = new Form();
        tokenRequest.param(GRANT_TYPE, "authorization_code")
                .param(CLIENT_ID, SimpleIdProvider.CLIENT_ID)
                .param(CODE, code);
        JsonObject token = client.target(config.getString("token_endpoint"))
                .request()
                .post(Entity.form(tokenRequest), JsonObject.class);
        String accessToken = token.getString("access_token");
        JsonObject userinfo = client.target(config.getString("userinfo_endpoint"))
                .request().header("Authorization", "Bearer " + accessToken)
                .get(JsonObject.class);
        assertNotNull(userinfo, "User info should be returned");

        JWKSet keyset = JWKSet.load(URI.create(config.getString("jwks_uri")).toURL());
        SignedJWT jwt = SignedJWT.parse(token.getString("id_token"));
        JWSHeader jwsHeader = jwt.getHeader();
        List<JWK> matches = new JWKSelector(JWKMatcher.forJWSHeader(jwsHeader))
                .select(keyset);

        if (!matches.isEmpty()) {
            assertTrue(jwt.verify(new RSASSAVerifier(matches.get(0).toRSAKey())), "JWT should pass signature validation");
        } else {
            fail("No key from keyset matched signature of JWT");
        }

    }
}
