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

import fish.payara.security.openid.api.ClientAuthenticationMethod;
import fish.payara.security.openid.api.OpenIdConstant;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Implementation of the client authentication method 'client_secret_post'.
 *
 * @see "OpenID Connect Core 1.0, Section 9
 * <https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.9>"
 */
public class ClientSecretPost implements ClientAuthentication {
    // The Client identifier
    private final String clientId;
    // The Client secret
    private final char[] clientSecret;

    /**
     * Creates a {@link ClientAuthentication} which will use the client authentication method
     * `client_secret_post`.
     *
     * @param clientId     the OpenId Client identifier
     * @param clientSecret the OpenId Client secret
     */
    public ClientSecretPost(final String clientId, final char[] clientSecret) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ClientAuthenticationMethod getAuthenticationMethod() {
        return ClientAuthenticationMethod.CLIENT_SECRET_POST;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final Map<String, String> getRequestParameters() {
        final Map<String, String> additionalParameters = new HashMap<>();
        additionalParameters.put(OpenIdConstant.CLIENT_ID, clientId);
        additionalParameters.put(OpenIdConstant.CLIENT_SECRET, String.valueOf(clientSecret));
        return additionalParameters;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return "ClientSecretPost{" +
                "clientId='" + clientId + '\'' +
                ", clientSecret='" + Arrays.toString(clientSecret) + '\'' +
                '}';
    }
}