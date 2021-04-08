/*
 * Copyright (c) 2020 Payara Foundation and/or its affiliates. All rights reserved.
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

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import fish.payara.security.openid.api.IdentityToken;
import fish.payara.security.openid.api.RefreshToken;
import fish.payara.security.openid.domain.AccessTokenImpl;
import fish.payara.security.openid.domain.IdentityTokenImpl;
import fish.payara.security.openid.domain.OpenIdConfiguration;
import fish.payara.security.openid.domain.OpenIdNonce;
import fish.payara.security.openid.api.OpenIdConstant;

import static java.util.Collections.emptyMap;
import java.util.Map;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Form;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import javax.ws.rs.core.Response;

/**
 * Controller for Token endpoint
 *
 * @author Gaurav Gupta
 */
@ApplicationScoped
public class TokenController {

    @Inject
    private NonceController nonceController;

    @Inject
    OpenIdConfiguration configuration;

    /**
     * (4) A Client makes a token request to the token endpoint and the OpenId
     * Provider responds with an ID Token and an Access Token.
     *
     * @param request
     * @return a JSON object representation of OpenID Connect token response
     * from the Token endpoint.
     */
    public Response getTokens(HttpServletRequest request) {
        /**
         * one-time authorization code that RP exchange for an Access / Id token
         */
        String authorizationCode = request.getParameter(OpenIdConstant.CODE);

        /**
         * The Client sends the parameters to the Token Endpoint using the Form
         * Serialization with all parameters to :
         *
         * 1. Authenticate client using CLIENT_ID & CLIENT_SECRET <br>
         * 2. Verify that the Authorization Code is valid <br>
         * 3. Ensure that the redirect_uri parameter value is identical to the
         * initial authorization request's redirect_uri parameter value.
         */
        Form form = new Form()
                .param(OpenIdConstant.CLIENT_ID, configuration.getClientId())
                .param(OpenIdConstant.CLIENT_SECRET, new String(configuration.getClientSecret()))
                .param(OpenIdConstant.GRANT_TYPE, OpenIdConstant.AUTHORIZATION_CODE)
                .param(OpenIdConstant.CODE, authorizationCode)
                .param(OpenIdConstant.REDIRECT_URI, configuration.buildRedirectURI(request));

        //  ID Token and Access Token Request
        Client client = ClientBuilder.newClient();
        WebTarget target = client.target(configuration.getProviderMetadata().getTokenEndpoint());
        return target.request()
                .accept(APPLICATION_JSON)
                .post(Entity.form(form));
    }

    /**
     * (5.1) Validate Id Token's claims and verify ID Token's signature.
     *
     * @param idToken
     * @param httpContext
     * @return JWT Claims
     */
    public JWTClaimsSet validateIdToken(IdentityTokenImpl idToken, HttpMessageContext httpContext) {
        JWTClaimsSet claimsSet;
        HttpServletRequest request = httpContext.getRequest();
        HttpServletResponse response = httpContext.getResponse();

        /**
         * The nonce in the returned ID Token is compared to the hash of the
         * session cookie to detect ID Token replay by third parties.
         */
        String expectedNonceHash = null;
        if (configuration.isUseNonce()) {
            OpenIdNonce expectedNonce = nonceController.get(configuration, request, response);
            expectedNonceHash = nonceController.getNonceHash(expectedNonce);
        }

        try {
            JWTClaimsSetVerifier jwtVerifier = new IdTokenClaimsSetVerifier(expectedNonceHash, configuration);
            claimsSet = configuration.getJWTValidator().validateBearerToken(idToken.getTokenJWT(), jwtVerifier);
        } finally {
            nonceController.remove(configuration, request, response);
        }

        return claimsSet;
    }

    /**
     * Validate Id Token received from Successful Refresh Response.
     *
     * @param previousIdToken
     * @param newIdToken
     * @param httpContext
     * @return JWT Claims
     */
    public JWTClaimsSet validateRefreshedIdToken(IdentityToken previousIdToken, IdentityTokenImpl newIdToken, HttpMessageContext httpContext) {
        JWTClaimsSetVerifier jwtVerifier = new RefreshedIdTokenClaimsSetVerifier(previousIdToken, configuration);
        JWTClaimsSet claimsSet = configuration.getJWTValidator().validateBearerToken(newIdToken.getTokenJWT(), jwtVerifier);
        return claimsSet;
    }

    /**
     * (5.2) Validate the Access Token & it's claims and verify the signature.
     *
     * @param accessToken
     * @param idTokenAlgorithm
     * @param idTokenClaims
     * @return JWT Claims
     */
    public Map<String, Object> validateAccessToken(AccessTokenImpl accessToken, Algorithm idTokenAlgorithm, Map<String, Object> idTokenClaims) {
        Map<String, Object> claims = emptyMap();

        AccessTokenClaimsSetVerifier jwtVerifier = new AccessTokenClaimsSetVerifier(
                accessToken,
                idTokenAlgorithm,
                idTokenClaims,
                configuration
        );

        // https://support.okta.com/help/s/article/Signature-Validation-Failed-on-Access-Token
//        if (accessToken.getType() == AccessToken.Type.BEARER) {
//            JWTClaimsSet claimsSet = validateBearerToken(accessToken.getTokenJWT(), jwtVerifier, configuration);
//            claims = claimsSet.getClaims();
//        } else {
            jwtVerifier.validateAccessToken();
//        }

        return claims;
    }

    /**
     * Makes a refresh request to the token endpoint and the OpenId Provider
     * responds with a new (updated) Access Token and Refreshs Token.
     *
     * @param refreshToken Refresh Token received from previous token request.
     * @return a JSON object representation of OpenID Connect token response
     * from the Token endpoint.
     */
    public Response refreshTokens(RefreshToken refreshToken) {

        Form form = new Form()
                .param(OpenIdConstant.CLIENT_ID, configuration.getClientId())
                .param(OpenIdConstant.CLIENT_SECRET, new String(configuration.getClientSecret()))
                .param(OpenIdConstant.GRANT_TYPE, OpenIdConstant.REFRESH_TOKEN)
                .param(OpenIdConstant.REFRESH_TOKEN, refreshToken.getToken());

        // Access Token and RefreshToken Request
        Client client = ClientBuilder.newClient();
        WebTarget target = client.target(configuration.getProviderMetadata().getTokenEndpoint());
        return target.request()
                .accept(APPLICATION_JSON)
                .post(Entity.form(form));
    }





}
