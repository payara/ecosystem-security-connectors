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

package fish.payara.security.openid.adfs;

import java.net.URI;
import java.util.Date;

import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import fish.payara.security.openid.idp.AbstractIdProvider;
import fish.payara.security.openid.idp.AuthCode;
import fish.payara.security.openid.idp.Token;

@Path("idp")
public class AdfsEmulation extends AbstractIdProvider {
    @Override
    protected Object authenticate(AuthRequest request) throws AuthException {
        return "testuser";
    }

    @Override
    protected void customizeConfig(JsonObjectBuilder baseConfig, URI providerRoot) {
        baseConfig.add("access_token_issuer", "http://someone-else");
    }

    @Override
    protected Token exchangeToken(TokenRequest request) throws AuthException {
        if ("gimme".equals(request.getGrantType())) {
            Token result = new Token();
            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                    .audience("test_client")
                    .subject("test_subject")
                    .expirationTime(result.getExpirationTime())
                    .issuer(providerRoot(uriInfo).toString())
                    .notBeforeTime(new Date())
                    .issueTime(new Date());
            result.setIdToken(builder);
            builder.issuer("http://someone-else");
            result.setAccessToken(builder);
            return result;
        }
        throw new AuthException("not_supported");
    }

    @Override
    protected Token exchangeToken(AuthCode code) throws AuthException {
        Token result = new Token();
        result.setIdToken(result.claimsFor(code, providerRoot(uriInfo), "test_object"));
        result.setAccessToken(result.claimsFor(code, URI.create("http://someone-else"), "test_object"));
        return result;
    }

    @Override
    protected JWT encodeJWT(JWTClaimsSet claims) throws JOSEException {
        return rs256(claims);
    }

    @Override
    protected JWKSet getKeyset() {
        return new JWKSet(rsaKey());
    }

    @Override
    protected JsonObject userInfo(Token token) {
        throw new NotAuthorizedException("ADFS throws 401 here", (Response) null);
    }
}
