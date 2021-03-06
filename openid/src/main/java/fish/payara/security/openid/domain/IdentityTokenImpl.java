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
import com.nimbusds.jwt.JWTParser;
import fish.payara.security.openid.api.IdentityToken;
import static fish.payara.security.openid.api.OpenIdConstant.EXPIRATION_IDENTIFIER;
import java.text.ParseException;
import static java.util.Collections.emptyMap;
import java.util.Date;
import java.util.Map;
import static java.util.Objects.nonNull;

/**
 *
 * @author Gaurav Gupta
 */
public class IdentityTokenImpl implements IdentityToken {

    private final String token;

    private final JWT tokenJWT;

    private Map<String, Object> claims;

    private OpenIdConfiguration configuration;

    public IdentityTokenImpl(OpenIdConfiguration configuration, String token) {
        this.configuration = configuration;
        this.token = token;
        try {
            this.tokenJWT = JWTParser.parse(token);
            this.claims = tokenJWT.getJWTClaimsSet().getClaims();
        } catch (ParseException ex) {
            throw new IllegalStateException("Error in parsing the Token", ex);
        }
    }

    public JWT getTokenJWT() {
        return tokenJWT;
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

    public boolean isEncrypted() {
        return tokenJWT != null && tokenJWT instanceof EncryptedJWT;
    }

    public boolean isSigned() {
        return tokenJWT != null && tokenJWT instanceof EncryptedJWT;
    }

    @Override
    public boolean isExpired() {
        boolean expired = true;
        Date exp;
        if (nonNull(exp = (Date) this.getClaim(EXPIRATION_IDENTIFIER))) {
            expired = System.currentTimeMillis() + configuration.getTokenMinValidity() > exp.getTime();
        } else {
            throw new IllegalStateException("Missing expiration time (exp) claim in identity token");
        }
        return expired;
    }

    @Override
    public String toString() {
        return token;
    }
}
