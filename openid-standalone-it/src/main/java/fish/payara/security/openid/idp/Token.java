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

package fish.payara.security.openid.idp;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.function.Function;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;

public class Token {
    public String refreshToken;

    private JWTClaimsSet idToken;

    private JWTClaimsSet accessTokenJwt;

    private String accessTokenString;

    private Instant validityStart = Instant.now();

    private Duration duration = Duration.ofMinutes(5);


    public JWTClaimsSet getIdToken() {
        return idToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public Instant getValidityStart() {
        return validityStart;
    }

    public Duration getDuration() {
        return duration;
    }

    public long getDurationInSeconds() {
        return duration.toMillis() / 1000;
    }

    public String getAccessToken(Function<JWTClaimsSet, JWT> tokenGenerator) {
        if (accessTokenJwt != null) {
            return tokenGenerator.apply(accessTokenJwt).serialize();
        } else {
            return accessTokenString;
        }
    }

    public JWTClaimsSet.Builder claimsFor(AuthCode code, URI issuer, String subject) {
        return new JWTClaimsSet.Builder()
                .audience(code.getClientId())
                .subject(subject)
                .expirationTime(new Date(validityStart.plus(duration).toEpochMilli()))
                .issuer(issuer.toString())
                .notBeforeTime(new Date())
                .issueTime(new Date())
                .claim("nonce", code.getNonce());
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public void setIdToken(JWTClaimsSet idToken) {
        this.idToken = idToken;
    }

    public void setIdToken(JWTClaimsSet.Builder idToken) {
        this.idToken = idToken.build();
    }

    public void setAccessToken(JWTClaimsSet accessTokenJwt) {
        this.accessTokenString = null;
        this.accessTokenJwt = accessTokenJwt;
    }

    public void setAccessToken(JWTClaimsSet.Builder accessToken) {
        setAccessToken(accessToken.build());
    }

    public void setAccessToken(String accessTokenString) {
        this.accessTokenString = accessTokenString;
        this.accessTokenJwt = null;
    }
}
