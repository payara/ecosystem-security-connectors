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
package fish.payara.security.openid.api;

import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableList;
import java.util.List;

/**
 * Contains constant specific to OpenId Connect specification
 * http://openid.net/specs/openid-connect-core-1_0.html
 *
 * @author Gaurav Gupta
 */
public interface OpenIdConstant {

    // Authorization Code request/response parameters
    String RESPONSE_TYPE = "response_type";
    String CLIENT_ID = "client_id";
    String SCOPE = "scope";
    String REDIRECT_URI = "redirect_uri";
    String RESPONSE_MODE = "response_mode";
    String STATE = "state";
    String NONCE = "nonce";
    String DISPLAY = "display";
    String PROMPT = "prompt";
    String MAX_AGE = "max_age";
    String UI_LOCALES = "ui_locales";
    String CLAIMS_LOCALES = "claims_locales";
    String ID_TOKEN_HINT = "id_token_hint";
    String LOGIN_HINT = "login_hint";
    String ACR_VALUES = "acr_values";
    String CODE = "code";
    String POST_LOGOUT_REDIRECT_URI = "post_logout_redirect_uri";

    // Access Token request/response parameters
    String GRANT_TYPE = "grant_type";
    String AUTHORIZATION_CODE = "authorization_code";
    String CLIENT_SECRET = "client_secret";
    String ACCESS_TOKEN = "access_token";
    String IDENTITY_TOKEN = "id_token";
    String TOKEN_TYPE = "token_type";
    String EXPIRES_IN = "expires_in";
    String REFRESH_TOKEN = "refresh_token";
    String ERROR_PARAM = "error";
    String ERROR_DESCRIPTION_PARAM = "error_description";

    //claims
    String ISSUER_IDENTIFIER = "iss";
    String SUBJECT_IDENTIFIER = "sub";
    String EXPIRATION_IDENTIFIER = "exp";
    String AUDIENCE = "aud";
    String AUTHORIZED_PARTY = "azp";
    String ACCESS_TOKEN_HASH = "at_hash";

    // OpenID Provider Metadata
    String AUTHORIZATION_ENDPOINT = "authorization_endpoint";
    String TOKEN_ENDPOINT = "token_endpoint";
    String USERINFO_ENDPOINT = "userinfo_endpoint";
    String END_SESSION_ENDPOINT = "end_session_endpoint";
    String REGISTRATION_ENDPOINT = "registration_endpoint";
    String JWKS_URI = "jwks_uri";

    String ISSUER = "issuer";
    String SCOPES_SUPPORTED = "scopes_supported";
    String ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED = "id_token_signing_alg_values_supported";
    String ID_TOKEN_ENCRYPTION_ALG_VALUES_SUPPORTED = "id_token_encryption_alg_values_supported";
    String ID_TOKEN_ENCRYPTION_ENC_VALUES_SUPPORTED = "id_token_encryption_enc_values_supported";
    String RESPONSE_TYPES_SUPPORTED = "response_types_supported";
    String RESPONSE_MODES_SUPPORTED = "response_modes_supported";
    String TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED = "token_endpoint_auth_methods_supported";
    String TOKEN_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED = "token_endpoint_auth_signing_alg_values_supported";
    String DISPLAY_VALUES_SUPPORTED = "display_values_supported";
    String CLAIMS_SUPPORTED = "claims_supported";
    String CLAIM_TYPES_SUPPORTED = "claim_types_supported";
    String SUBJECT_TYPES_SUPPORTED = "subject_types_supported";

    List<String> AUTHORIZATION_CODE_FLOW_TYPES
            = unmodifiableList(asList(
                    "code"
            ));
    List<String> IMPLICIT_FLOW_TYPES
            = unmodifiableList(asList(
                    "id_token",
                    "id_token token"
            ));
    List<String> HYBRID_FLOW_TYPES
            = unmodifiableList(asList(
                    "code id_token",
                    "code token",
                    "code id_token token"
            ));

    // Scopes
    String OPENID_SCOPE = "openid"; //required
    String PROFILE_SCOPE = "profile";
    String EMAIL_SCOPE = "email";
    String PHONE_SCOPE = "phone";
    String OFFLINE_ACCESS_SCOPE = "offline_access";

    // profile scope claims
    String NAME = "name";
    String FAMILY_NAME = "family_name";
    String GIVEN_NAME = "given_name";
    String MIDDLE_NAME = "middle_name";
    String NICKNAME = "nickname";
    String PREFERRED_USERNAME = "preferred_username";
    String GROUPS = "groups";
    String PROFILE = "profile";
    String PICTURE = "picture";
    String WEBSITE = "website";
    String GENDER = "gender";
    String BIRTHDATE = "birthdate";
    String ZONEINFO = "zoneinfo";
    String LOCALE = "locale";
    String UPDATED_AT = "updated_at";

    // email scope claims
    String EMAIL = "email";
    String EMAIL_VERIFIED = "email_verified";

    // address scope claims
    String ADDRESS = "address";

    // phone scope claims
    String PHONE_NUMBER = "phone_number";
    String PHONE_NUMBER_VERIFIED = "phone_number_verified";

    String DEFAULT_JWT_SIGNED_ALGORITHM = "RS256";
    String DEFAULT_HASH_ALGORITHM = "SHA-256";

    // Authorization headers
    String AUTHORIZATION_HEADER = "Authorization";
    String BEARER_TYPE = "Bearer ";

}
