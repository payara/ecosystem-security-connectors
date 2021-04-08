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
package fish.payara.security.openid.domain;

import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import fish.payara.security.openid.api.AccessToken;
import java.text.ParseException;
import static java.util.Collections.emptyMap;
import java.util.Map;

import fish.payara.security.openid.api.JwtClaims;
import fish.payara.security.openid.api.Scope;
import fish.payara.security.openid.api.OpenIdConstant;

import java.util.Date;
import java.util.Optional;

import static java.util.Objects.nonNull;

/**
 *
 * @author Gaurav Gupta
 */
public class AccessTokenImpl implements AccessToken {

    private final String token;
    private final long tokenMinValidity;

    private final AccessToken.Type type;

    private final JwtClaims jwtClaims;

    private JWT tokenJWT;

    private Map<String, Object> claims;

    private final Long expiresIn;

    private final Scope scope;

    private final long createdAt;

    public AccessTokenImpl(String tokenType, String token, Long expiresIn, String scopeValue, long tokenMinValidity) {
        this.token = token;
        this.tokenMinValidity = tokenMinValidity;
        JWTClaimsSet jwtClaimsSet = null;
        try {
            this.tokenJWT = JWTParser.parse(token);
            jwtClaimsSet = tokenJWT.getJWTClaimsSet();
            this.claims = jwtClaimsSet.getClaims();
        } catch (ParseException ex) {
            // Access token doesn't need to be JWT at all
        }
        this.jwtClaims = NimbusJwtClaims.ifPresent(jwtClaimsSet);

        this.type = Type.valueOf(tokenType.toUpperCase());
        this.expiresIn = expiresIn;
        this.createdAt = System.currentTimeMillis();
        this.scope = Scope.parse(scopeValue);
    }

    private AccessTokenImpl(JWT token, JWTClaimsSet claims, long tokenMinValidity) {
        this.token = token.getParsedString();
        this.tokenJWT = token;
        this.claims = claims.getClaims();
        this.jwtClaims = NimbusJwtClaims.ifPresent(claims);
        this.type = Type.BEARER;
        this.expiresIn = null;
        this.createdAt = System.currentTimeMillis();
        this.scope = jwtClaims.getStringClaim(OpenIdConstant.SCOPE).map(Scope::parse).orElse(null);
        this.tokenMinValidity = tokenMinValidity;
    }

    public static AccessTokenImpl forBearerToken(OpenIdConfiguration configuration, String rawToken, JWTClaimsSetVerifier validator) throws ParseException {
        JWT token = JWTParser.parse(rawToken);
        JWTClaimsSet claims = configuration.getJWTValidator().validateBearerToken(token, validator);
        return new AccessTokenImpl(token, claims, configuration.getTokenMinValidity());
    }

    public JWT getTokenJWT() {
        return tokenJWT;
    }

    @Override
    public boolean isExpired() {
        boolean expired = true;
        Date exp;
         if (nonNull(expiresIn)) {
            expired = System.currentTimeMillis() + tokenMinValidity > createdAt + (expiresIn * 1000);
        } else if(nonNull(exp = (Date) this.getClaim(OpenIdConstant.EXPIRATION_IDENTIFIER))) {
            expired = System.currentTimeMillis() + tokenMinValidity > exp.getTime();
        } else {
            throw new IllegalStateException("Missing expiration time (exp) claim in access token");
        }
        return expired;
    }

    @Override
    public Type getType() {
        return type;
    }

    @Override
    public String getToken() {
        return token;
    }

    @Override
    public Map<String, Object> getClaims() {
        if (claims == null) {
            return emptyMap();
        }
        return claims;
    }

    public void setClaims(Map<String, Object> claims) {
        this.claims = claims;
    }

    @Override
    public Object getClaim(String key) {
        return getClaims().get(key);
    }

    @Override
    public Long getExpirationTime() {
        return expiresIn;
    }

    @Override
    public Scope getScope() {
        return scope;
    }

    @Override
    public boolean isJWT() {
        return tokenJWT != null;
    }

    @Override
    public JwtClaims getJwtClaims() {
        return jwtClaims;
    }

    public boolean isEncrypted() {
        return isJWT() && tokenJWT instanceof EncryptedJWT;
    }

    public boolean isSigned() {
        return isJWT() && tokenJWT instanceof SignedJWT;
    }

    @Override
    public String toString() {
        return token;
    }

}
