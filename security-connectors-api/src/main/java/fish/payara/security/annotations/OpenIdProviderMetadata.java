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
package fish.payara.security.annotations;

import java.lang.annotation.Retention;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

/**
 * {@link OpenIdProviderMetadata} annotation overrides the openid connect provider's endpoint value, discovered using
 * providerUri.
 *
 * The documentation: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
 *
 * @author Gaurav Gupta
 * @author Petr Aubrecht
 */
@Retention(RUNTIME)
public @interface OpenIdProviderMetadata {

    /**
     * Required, FIXME: keep optional for backward compatibility. The base address of OpenId Connect Provider.
     * <p>
     * URL using the https scheme with no query or fragment component that the OP asserts as its Issuer Identifier.
     * </p>
     * To set this using Microprofile Config use {@code payara.security.openid.provider.issuer}
     *
     * @return
     */
    String issuer() default "";

    /**
     * Required. The URL for the OAuth2 provider to provide authentication
     * <p>
     * This must be a https endpoint.
     * </p>
     * To set this using Microprofile Config use
     * {@code payara.security.openid.provider.authorizationEndpoint}.
     *
     * @return
     */
    String authorizationEndpoint() default "";

    /**
     * Required. The URL for the OAuth2 provider to give the authorization token
     * <p>
     * To set this using Microprofile Config use
     * {@code payara.security.openid.provider.tokenEndpoint}
     * </p>
     *
     * @return
     */
    String tokenEndpoint() default "";

    /**
     * Required. An OAuth 2.0 Protected Resource that returns Claims about the
     * authenticated End-User.
     * <p>
     * To set this using Microprofile Config use
     * {@code payara.security.openid.provider.userinfoEndpoint}
     * </p>
     *
     * @return
     */
    String userinfoEndpoint() default "";

    /**
     * Optional. OP endpoint to notify that the End-User has logged out of the
     * site and might want to log out of the OP as well.
     * <p>
     * To set this using Microprofile Config use
     * {@code payara.security.openid.provider.endSessionEndpoint}
     * </p>
     *
     * @return
     */
    String endSessionEndpoint() default "";

    /**
     * Required. An OpenId Connect Provider's JSON Web Key Set document
     * <p>
     * This contains the signing key(s) the RP uses to validate signatures from
     * the OP. The JWK Set may also contain the Server's encryption key(s),
     * which are used by RPs to encrypt requests to the Server.
     * </p>
     * To set this using Microprofile Config use
     * {@code payara.security.openid.provider.jwksURI}
     *
     * @return
     */
    String jwksURI() default "";

    //NOT USED: registration_endpoint
    //RECOMMENDED. URL of the OP's Dynamic Client Registration Endpoint.
    //
    /**
     * Recommended. JSON array containing a list of the OAuth 2.0 [RFC6749] scope values that this server supports.
     *
     * To set this using Microprofile Config use {@code payara.security.openid.provider.scopesSupported}
     *
     * @return
     */
    String[] scopesSupported() default {};//{"openid"};

    /**
     * Required. JSON array containing a list of the OAuth 2.0 response_type values that this OP supports.
     *
     * To set this using Microprofile Config use {@code payara.security.openid.provider.responseTypeSupported}
     *
     * @return
     */
    String[] responseTypesSupported() default {};//{"code", "id_token", "token id_token"};

    // NOT USED
    // response_modes_supported
    //    OPTIONAL. JSON array containing a list of the OAuth 2.0 response_mode values that this OP supports, as specified in OAuth 2.0 Multiple Response Type Encoding Practices [OAuth.Responses]. If omitted, the default for Dynamic OpenID Providers is ["query", "fragment"].
    // grant_types_supported
    //    OPTIONAL. JSON array containing a list of the OAuth 2.0 Grant Type values that this OP supports. Dynamic OpenID Providers MUST support the authorization_code and implicit Grant Type values and MAY support other Grant Types. If omitted, the default value is ["authorization_code", "implicit"].
    // acr_values_supported
    //    OPTIONAL. JSON array containing a list of the Authentication Context Class References that this OP supports.
    //
    /**
     * Required. JSON array containing a list of the Subject Identifier types that this OP supports. Valid types include
     * pairwise and public.
     *
     * To set this using Microprofile Config use {@code payara.security.openid.provider.subjectTypesSupported}
     *
     * @return
     */
    String[] subjectTypesSupported() default {};//{"public"};

    /**
     * Required. REQUIRED. JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP
     * for the ID Token to encode the Claims in a JWT.
     *
     * To set this using Microprofile Config use
     * {@code payara.security.openid.provider.idTokenSigningAlgorithmsSupported}
     *
     * @return
     */
    String[] idTokenSigningAlgValuesSupported() default {};//{"RS256"};

    /**
     * Optional. JSON array containing a list of the JWE encryption algorithms (alg values) supported by the OP for the
     * ID Token to encode the Claims in a JWT.
     *
     * To set this using Microprofile Config use
     * {@code payara.security.openid.provider.idTokenEncryptionAlgValuesSupported}
     *
     * @return
     */
    String[] idTokenEncryptionAlgValuesSupported() default {};

    /**
     * Optional. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for the
     * ID Token to encode the Claims in a JWT.
     *
     * To set this using Microprofile Config use
     * {@code payara.security.openid.provider.idTokenEncryptionEncValuesSupported}
     *
     * @return
     */
    String[] idTokenEncryptionEncValuesSupported() default {};

    /**
     * Recommended. JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be able
     * to supply values for. Note that for privacy or other reasons, this might not be an exhaustive list.
     *
     * To set this using Microprofile Config use
     * {@code payara.security.openid.provider.claimsSupported}
     *
     * @return
     */
    String[] claimsSupported() default {};

    /**
     * The Microprofile Config key for the issuer url is <code>{@value}</code>.
     */
    String OPENID_MP_ISSUER = "payara.security.openid.provider.issuer";

    /**
     * The Microprofile Config key for the auth endpoint is <code>{@value}</code>
     */
    String OPENID_MP_AUTHORIZATION_ENDPOINT = "payara.security.openid.provider.authorizationEndpoint";

    /**
     * The Microprofile Config key for the token Endpoint is
     * <code>{@value}</code>
     */
    String OPENID_MP_TOKEN_ENDPOINT = "payara.security.openid.provider.tokenEndpoint";

    /**
     * The Microprofile Config key for the userinfo Endpoint is
     * <code>{@value}</code>
     */
    String OPENID_MP_USERINFO_ENDPOINT = "payara.security.openid.provider.userinfoEndpoint";

   /**
     * The Microprofile Config key for the end session Endpoint is     * <code>{@value}</code>
     */
    public static final String OPENID_MP_END_SESSION_ENDPOINT = "payara.security.openid.provider.endSessionEndpoint";

    /**
     * The Microprofile Config key for the jwks uri is <code>{@value}</code>
     */
    String OPENID_MP_JWKS_URI = "payara.security.openid.provider.jwksURI";

    /**
     * The Microprofile Config key for the scopes supported is <code>{@value}</code>
     */
    String OPENID_MP_SCOPES_SUPPORTED = "payara.security.openid.provider.scopesSupported";

    /**
     * The Microprofile Config key for the response types supported is <code>{@value}</code>
     */
    String OPENID_MP_RESPONSE_TYPES_SUPPORTED = "payara.security.openid.provider.responseTypesSupported";

    /**
     * The Microprofile Config key for the subjects types supported is <code>{@value}</code>
     */
    String OPENID_MP_SUBJECT_TYPES_SUPPORTED = "payara.security.openid.provider.subjectTypesSupported";

    /**
     * The Microprofile Config key for the signing algorithms supported is <code>{@value}</code>
     */
    String OPENID_MP_ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED = "payara.security.openid.provider.idTokenSigningAlgValuesSupported";
    /**
     * The Microprofile Config key for the encryption algorighm alg - values supported is <code>{@value}</code>
     */
    String OPENID_MP_ID_TOKEN_ENCRYPTION_ALG_VALUES_SUPPORTED = "payara.security.openid.provider.idTokenEncryptionAlgValuesSupported";

    /**
     * The Microprofile Config key for the encryption algorighm enc - values supported is <code>{@value}</code>
     */
    String OPENID_MP_ID_TOKEN_ENCRYPTION_ENC_VALUES_SUPPORTED = "payara.security.openid.provider.idTokenEncryptionEncValuesSupported";

    /**
     * The Microprofile Config key for the supported claims supported is <code>{@value}</code>
     */
    String OPENID_MP_CLAIMS_SUPPORTED = "payara.security.openid.provider.claimsSupported";

}
