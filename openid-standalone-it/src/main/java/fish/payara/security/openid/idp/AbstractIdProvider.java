/*
 *  DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 *  Copyright (c) [2018-2021] Payara Foundation and/or its affiliates. All rights reserved.
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
package fish.payara.security.openid.idp;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.ws.rs.BeanParam;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import static fish.payara.security.connectors.openid.api.OpenIdConstant.*;
import static java.util.logging.Level.INFO;
import static java.util.logging.Level.SEVERE;
import static javax.ws.rs.core.MediaType.APPLICATION_FORM_URLENCODED;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

/**
 * @author Gaurav Gupta
 * @author Patrik Dudits
 */
public abstract class AbstractIdProvider {


    static final String AUTHORIZATION_HEADER = "Authorization";

    static final String BEARER_TYPE = "Bearer";

    private static final ConcurrentMap<String, AuthCode> codeRepo = new ConcurrentHashMap<>();

    private static final ConcurrentMap<String, Token> tokenRepo = new ConcurrentHashMap<>();

    protected static void clear() {
        tokenRepo.clear();
        codeRepo.clear();
    }

    private final Logger LOGGER = Logger.getLogger(getClass().getName());

    @Path(".well-known/openid-configuration")
    @GET
    @Produces
    public Response getConfiguration(@Context UriInfo uri) {

        URI providerRoot = providerRoot(uri);
        JsonObjectBuilder baseConfig = Json.createObjectBuilder()
                .add("issuer", providerRoot.toString())
                .add("authorization_endpoint", providerRoot.resolve("auth").toString())
                .add("token_endpoint", providerRoot.resolve("token").toString())
                .add("userinfo_endpoint", providerRoot.resolve("userinfo").toString())
                .add("jwks_uri", providerRoot.resolve("jwks").toString())
                .add("scopes_supported", Json.createArrayBuilder().add("openid").add("email").add("profile"))
                .add("response_types_supported", Json.createArrayBuilder().add("code").add("id_token").add("token id_token"))
                .add("subject_types_supported", Json.createArrayBuilder().add("public"))
                .add("id_token_signing_alg_values_supported", Json.createArrayBuilder().add("RS256").add("none"))
                .add("claims_supported", Json.createArrayBuilder().add("aud").add("email"));

        customizeConfig(baseConfig, providerRoot);
        return Response.ok(baseConfig.build())
                .header("Access-Control-Allow-Origin", "*")
                .build();
    }

    protected URI providerRoot(UriInfo uri) {
        URI providerRoot = uri.getRequestUri().resolve("../");
        return providerRoot;
    }

    protected void customizeConfig(JsonObjectBuilder baseConfig, URI providerRoot) {

    }

    @Path("auth")
    @GET
    @Produces
    public Response authEndpoint(@BeanParam AuthRequest authRequest) throws URISyntaxException {
        try {
            AuthCode result = new AuthCode(authRequest);
            result.setIdentity(authenticate(authRequest));
            codeRepo.put(result.getCode(), result);
            UriBuilder redirectBuilder = UriBuilder.fromUri(authRequest.redirectUri).queryParam(CODE, result.getCode());
            if (authRequest.getState() != null) {
                redirectBuilder.queryParam(STATE, authRequest.getState());
            }
            URI returnUrl = redirectBuilder.build();
            LOGGER.info("Authorization successful, redirecting to " + returnUrl);
            return Response.seeOther(returnUrl).build();
        } catch (AuthException ae) {
            LOGGER.log(INFO, "Authentication failed", ae);
            return Response.status(Response.Status.BAD_REQUEST).type(APPLICATION_JSON).entity(ae.asJson()).build();
        } catch (Exception e) {
            LOGGER.log(SEVERE, "Authentication Exception", e);
            return Response.serverError().type(APPLICATION_JSON).entity(new AuthException("server_error", null, authRequest.getState()).asJson()).build();
        }
    }

    /**
     * Validate authentication request and return any identity data to be used during token exchange.
     *
     * @param request
     * @return
     * @throws AuthException
     */
    protected abstract Object authenticate(AuthRequest request) throws AuthException;

    @Path("token")
    @POST
    @Consumes(APPLICATION_FORM_URLENCODED)
    public Response tokenEndpoint(@BeanParam TokenRequest tokenRequest, MultivaluedMap<String, String> allParams) {
        //TokenRequest tokenRequest = new TokenRequest(allParams);
        tokenRequest.allParams = allParams;

        try {
            Token result;
            if (AUTHORIZATION_CODE.equals(tokenRequest.grantType)) {
                AuthCode code = codeRepo.remove(tokenRequest.code);
                if (code == null) {
                    throw new AuthException("invalid_code");
                }
                result = exchangeToken(code);
            } else {
                result = exchangeToken(tokenRequest);
            }
            if (result == null) {
                throw new AuthException("invalid_code", "No token exchanged");
            }
            JsonObjectBuilder builder = Json.createObjectBuilder();
            JWT idToken = encodeJWT(result.getIdToken());
            String accessToken = result.getAccessToken(this::encodeJWTHandlingExceptions);
            builder.add(IDENTITY_TOKEN, idToken.serialize())
                    .add(ACCESS_TOKEN, accessToken)
                    .add(TOKEN_TYPE, BEARER_TYPE)
                    .add(EXPIRES_IN, result.getDurationInSeconds());
            if (result.getRefreshToken() != null) {
                builder.add("refresh_token", result.refreshToken);
            }
            tokenRepo.put(accessToken, result);
            return Response.ok().type(APPLICATION_JSON).entity(builder.build()).build();
        } catch (AuthException ae) {
            LOGGER.log(INFO, "Token exchange failed", ae);
            return Response.status(Response.Status.BAD_REQUEST).type(APPLICATION_JSON).entity(ae.asJson()).build();
        } catch (Exception e) {
            LOGGER.log(SEVERE, "Token exchange Exception", e);
            return Response.serverError().type(APPLICATION_JSON).entity(new AuthException("server_error").asJson()).build();
        }
    }

    private JWT encodeJWTHandlingExceptions(JWTClaimsSet set) {
        try {
            return encodeJWT(set);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    @Path("jwks")
    @GET
    public String getKeystore() {
        return getKeyset().toString(true);
    }

    protected JWKSet getKeyset() {
        return new JWKSet();
    }

    protected abstract Token exchangeToken(AuthCode code) throws AuthException;

    protected abstract Token exchangeToken(TokenRequest request) throws AuthException;

    protected abstract JWT encodeJWT(JWTClaimsSet claims) throws JOSEException;

    protected JWT rs256(JWTClaimsSet claims) throws JOSEException {
        SignedJWT signed = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey().getKeyID()).build(),
                claims);
        signed.sign(new RSASSASigner(rsaKey()));
        return signed;
    }

    protected JWT es256(JWTClaimsSet claims) throws JOSEException {
        SignedJWT signed = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(ecKey().getKeyID()).build(),
                claims);
        signed.sign(new ECDSASigner(ecKey()));
        return signed;
    }

    @Path("userinfo")
    @Produces(APPLICATION_JSON)
    @GET
    public Response userinfoEndpoint(@HeaderParam(AUTHORIZATION_HEADER) String authorizationHeader) {
        String accessToken = authorizationHeader.substring(BEARER_TYPE.length() + 1);
        Token token = tokenRepo.get(accessToken);

        try {
            if (token == null) {
                throw new AuthException("invalid_token");
            }
            // TODO: if access token is JWT, validate JWT
            JsonObject userInfo = userInfo(token);
            return Response.ok(userInfo).build();
        } catch (AuthException ae) {
            LOGGER.log(INFO, "User info failed", ae);
            return Response.status(Response.Status.BAD_REQUEST).entity(ae.asJson()).build();
        } catch (Exception e) {
            LOGGER.log(SEVERE, "User info Exception", e);
            return Response.serverError().entity(new AuthException("server_error").asJson()).build();
        }
    }


    protected static ECKey EC_KEY;

    protected static ECKey ecKey() {
        if (EC_KEY == null) {
            try {
                EC_KEY = new ECKeyGenerator(Curve.P_256).keyID("ec").generate();
            } catch (JOSEException e) {
            }
        }
        return EC_KEY;
    }

    protected static RSAKey RSA_KEY;

    protected static RSAKey rsaKey() {
        if (RSA_KEY == null) {
            try {
                RSA_KEY = new RSAKeyGenerator(2048)
                        .keyID("rsa")
                        .generate();
            } catch (JOSEException e) {
                throw new RuntimeException(e);
            }
        }
        return RSA_KEY;
    }

    protected abstract JsonObject userInfo(Token token);

    protected static class AuthException extends Exception {
        private final String errorCode;

        private final String state;

        public AuthException(String errorCode) {
            this(errorCode, null, null);
        }

        AuthException(String errorCode, String description, String state) {
            super(description);
            this.errorCode = Objects.requireNonNull(errorCode);
            this.state = state;
        }

        AuthException(String errorCode, String description) {
            this(errorCode, description, null);
        }

        JsonObject asJson() {
            JsonObjectBuilder builder = Json.createObjectBuilder()
                    .add("error", errorCode);
            if (getMessage() != null) {
                builder.add("error_description", getMessage());
            }
            if (state != null) {
                builder.add("state", state);
            }
            return builder.build();
        }
    }

    protected static class AuthRequest {
        @QueryParam(CLIENT_ID)
        String clientId;

        @QueryParam(SCOPE)
        String scope;

        @QueryParam(RESPONSE_TYPE)
        String responseType;

        @QueryParam(NONCE)
        String nonce;

        @QueryParam(STATE)
        String state;

        @QueryParam(REDIRECT_URI)
        String redirectUri;

        @Context
        UriInfo uriInfo;

        public String getClientId() {
            return clientId;
        }

        public String getScope() {
            return scope;
        }

        public String getResponseType() {
            return responseType;
        }

        public String getNonce() {
            return nonce;
        }

        public String getState() {
            return state;
        }

        public String getRedirectUri() {
            return redirectUri;
        }

        public String getParameter(String parameterName) {
            return uriInfo.getQueryParameters().getFirst(parameterName);
        }

        public List<String> getParameterValues(String parameterName) {
            return uriInfo.getQueryParameters().get(parameterName);
        }

        public boolean hasParameter(String parameterName) {
            return uriInfo.getQueryParameters().containsKey(parameterName);
        }

        public Iterable<String> parameterNames() {
            return uriInfo.getQueryParameters().keySet();
        }
    }

    protected static class TokenRequest {
        @FormParam(CLIENT_ID)
        String clientId;

        @FormParam(CLIENT_SECRET)
        String clientSecret;

        @FormParam(GRANT_TYPE)
        String grantType;

        @FormParam(CODE)
        String code;

        @FormParam(REDIRECT_URI)
        String redirectUri;


        private MultivaluedMap<String, String> allParams;

        public TokenRequest() {
            // for beanparams
        }

        public TokenRequest(MultivaluedMap<String, String> allParams) {
            this.allParams = allParams;
            clientId = allParams.getFirst(CLIENT_ID);
            clientSecret = allParams.getFirst(CLIENT_SECRET);
            grantType = allParams.getFirst(GRANT_TYPE);
            redirectUri = allParams.getFirst(REDIRECT_URI);
        }

        public String getParameter(String parameterName) {
            return allParams.getFirst(parameterName);
        }

        public List<String> getParameterValues(String parameterName) {
            return allParams.get(parameterName);
        }

        public boolean hasParameter(String parameterName) {
            return allParams.containsKey(parameterName);
        }

        public Iterable<String> parameterNames() {
            return allParams.keySet();
        }
    }


}
