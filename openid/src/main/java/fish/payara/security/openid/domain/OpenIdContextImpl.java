/*
 * Copyright (c) 2020-2021 Payara Foundation and/or its affiliates. All rights reserved.
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
package fish.payara.security.openid.domain;

import fish.payara.security.openid.api.AccessToken;
import fish.payara.security.openid.api.IdentityToken;
import fish.payara.security.openid.api.OpenIdClaims;
import fish.payara.security.openid.api.OpenIdContext;
import fish.payara.security.openid.api.RefreshToken;
import fish.payara.security.openid.api.JwtClaims;
import fish.payara.security.openid.api.OpenIdConstant;
import fish.payara.security.openid.controller.AuthenticationController;
import fish.payara.security.openid.OpenIdUtil;
import fish.payara.security.openid.controller.UserInfoController;

import java.io.IOException;
import java.util.Optional;
import static java.util.logging.Level.FINEST;
import static java.util.logging.Level.WARNING;
import java.util.logging.Logger;
import java.util.Set;
import jakarta.enterprise.context.SessionScoped;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.ws.rs.core.UriBuilder;

/**
 * An injectable interface that provides access to access token, identity token,
 * claims and OpenId Connect provider related information.
 *
 * @author Gaurav Gupta
 */
@SessionScoped
public class OpenIdContextImpl implements OpenIdContext {
    @Inject
    UserInfoController userInfoController;

    private String callerName;
    private Set<String> callerGroups;
    private String tokenType;
    private AccessToken accessToken;
    private IdentityToken identityToken;
    private RefreshToken refreshToken;
    private Long expiresIn;
    private JsonObject claims;

    @Inject
    private OpenIdConfiguration configuration;

    @Inject
    private AuthenticationController authenticationController;

    private static final Logger LOGGER = Logger.getLogger(OpenIdContextImpl.class.getName());

    @Override
    public String getCallerName() {
        return callerName;
    }

    public void setCallerName(String callerName) {
        this.callerName = callerName;
    }

    @Override
    public Set<String> getCallerGroups() {
        return callerGroups;
    }

    public void setCallerGroups(Set<String> callerGroups) {
        this.callerGroups = callerGroups;
    }

    @Override
    public String getSubject() {
        return (String) getIdentityToken().getClaim(OpenIdConstant.SUBJECT_IDENTIFIER);
    }

    @Override
    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    @Override
    public AccessToken getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(AccessToken token) {
        this.accessToken = token;
    }

    @Override
    public IdentityToken getIdentityToken() {
        return identityToken;
    }

    public void setIdentityToken(IdentityToken identityToken) {
        this.identityToken = identityToken;
    }

    @Override
    public Optional<RefreshToken> getRefreshToken() {
        return Optional.ofNullable(refreshToken);
    }

    public void setRefreshToken(RefreshToken refreshToken) {
        this.refreshToken = refreshToken;
    }

    @Override
    public Optional<Long> getExpiresIn() {
        return Optional.ofNullable(expiresIn);
    }

    public void setExpiresIn(Long expiresIn) {
        this.expiresIn = expiresIn;
    }

    @Override
    public JsonObject getClaimsJson() {
        if (claims == null) {
            if (configuration != null && accessToken != null) {
                if(!configuration.isUserClaimsFromIDToken()) {
                    claims = userInfoController.getUserInfo(configuration, accessToken);
                } else {
                    LOGGER.log(FINEST, "Processing user info from ID Token");
                    claims = processUserClaimsFromIDToken();
                }
            } else {
                claims = Json.createObjectBuilder().build();
            }
        }
        return claims;
    }

    /**
     * Method to get user information from Id Token
     * @return JsonObject with user information
     */
    private JsonObject processUserClaimsFromIDToken() {
        JwtClaims identityTokenJWTClaims = identityToken.getJwtClaims();
        JwtClaims accessTokenJWTClaims = accessToken.getJwtClaims();
        //setting profile claims from id token
        JsonObject userInfo = Json.createObjectBuilder()
                .add(OpenIdConstant.SUBJECT_IDENTIFIER, identityTokenJWTClaims.getStringClaim(OpenIdConstant.SUBJECT_IDENTIFIER).orElse(""))
                .add(OpenIdConstant.NAME, identityTokenJWTClaims.getStringClaim(OpenIdConstant.NAME).orElse(""))
                .add(OpenIdConstant.FAMILY_NAME, accessTokenJWTClaims.getStringClaim(OpenIdConstant.FAMILY_NAME).orElse(""))
                .add(OpenIdConstant.GIVEN_NAME, accessTokenJWTClaims.getStringClaim(OpenIdConstant.GIVEN_NAME).orElse(""))
                .add(OpenIdConstant.EMAIL, identityTokenJWTClaims.getStringClaim(OpenIdConstant.EMAIL).orElse("")).build();

        if(!this.getSubject().equals(userInfo.getString(OpenIdConstant.SUBJECT_IDENTIFIER))) {
            throw new IllegalStateException("UserInfo Response is invalid as sub claim must match with the sub Claim in the ID Token");
        }

        return userInfo;
    }

    @Override
    public OpenIdClaims getClaims() {
        return new JsonClaims(getClaimsJson());
    }

    @Override
    public JsonObject getProviderMetadata() {
        return configuration.getProviderMetadata().getDocument();
    }

    public void logout(HttpServletRequest request, HttpServletResponse response) {
        LogoutConfiguration logout = configuration.getLogoutConfiguration();
        try {
            request.logout();
        } catch (ServletException ex) {
            LOGGER.log(WARNING, "Failed to logout the user.", ex);
        }
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }

        if (logout == null) {
            LOGGER.log(WARNING, "Logout invoked on session without OpenID session");
            redirect(response, request.getContextPath());
        }
        /**
         * See section 5. RP-Initiated Logout
         * https://openid.net/specs/openid-connect-session-1_0.html#RPLogout
         */
        if (logout.isNotifyProvider()
                && !OpenIdUtil.isEmpty(configuration.getProviderMetadata().getEndSessionEndpoint())) {
            UriBuilder logoutURI = UriBuilder.fromUri(configuration.getProviderMetadata().getEndSessionEndpoint())
                    .queryParam(OpenIdConstant.ID_TOKEN_HINT, getIdentityToken().getToken());
            if (!OpenIdUtil.isEmpty(logout.getRedirectURI())) {
                // User Agent redirected to POST_LOGOUT_REDIRECT_URI after a logout operation performed in OP.
                logoutURI.queryParam(OpenIdConstant.POST_LOGOUT_REDIRECT_URI, logout.buildRedirectURI(request));
            }
            redirect(response, logoutURI.toString());
        } else if (!OpenIdUtil.isEmpty(logout.getRedirectURI())) {
            redirect(response, logout.buildRedirectURI(request));
        } else {
            // Redirect user to OpenID connect provider for re-authentication
            authenticationController.authenticateUser(request, response);
        }
    }

    private static void redirect(HttpServletResponse response, String uri) {
        try {
            response.sendRedirect(uri);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

}
