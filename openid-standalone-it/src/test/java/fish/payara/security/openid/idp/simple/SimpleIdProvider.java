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

import javax.enterprise.context.RequestScoped;
import javax.json.JsonObject;
import javax.json.JsonValue;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.UriInfo;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import fish.payara.security.openid.idp.AbstractIdProvider;
import fish.payara.security.openid.idp.AuthCode;
import fish.payara.security.openid.idp.Token;

@Path("simple/")
@RequestScoped
public class SimpleIdProvider extends AbstractIdProvider {
    public static final String CLIENT_ID = "test_client";

    @Context
    UriInfo uri;

    @Override
    protected Object authenticate(AuthRequest request) throws AuthException {
        if (CLIENT_ID.equals(request.getClientId())) {
            return "testuser";
        }
        throw new AuthException("invalid_credentials");
    }

    @Override
    protected Token exchangeToken(AuthCode code) throws AuthException {
        Token token = new Token();
        token.setIdToken(token.claimsFor(code, providerRoot(uri), String.valueOf(code.getIdentity())));
        token.setAccessToken("accesstoken");
        return token;
    }

    @Override
    protected JWKSet getKeyset() {
        return new JWKSet(rsaKey());
    }

    @Override
    protected Token exchangeToken(TokenRequest request) throws AuthException {
        throw new AuthException("not_supported");
    }

    @Override
    protected JWT encodeJWT(JWTClaimsSet claims) throws JOSEException {
        return rs256(claims);
    }

    @Override
    protected JsonObject userInfo(Token token) {
        return JsonValue.EMPTY_JSON_OBJECT;
    }
}
