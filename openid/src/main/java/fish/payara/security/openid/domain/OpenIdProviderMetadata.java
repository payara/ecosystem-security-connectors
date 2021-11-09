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

import java.net.URL;
import java.util.Set;
import javax.json.JsonObject;

/**
 * OpenId Connect provider information.
 *
 * @author Gaurav Gupta
 */
public class OpenIdProviderMetadata {

    private JsonObject document;
    private final String issuerURI;
    private String authorizationEndpoint;
    private String tokenEndpoint;
    private String userinfoEndpoint;
    private String endSessionEndpoint;
    private URL jwksURL;
    private final Set<String> scopesSupported;
    private final Set<String> claimsSupported;
    private final Set<String> responseTypesSupported;
    private final Set<String> idTokenSigningAlgValuesSupported;
    private final Set<String> idTokenEncryptionAlgValuesSupported;
    private final Set<String> idTokenEncryptionEncValuesSupported;
    private final Set<String> subjectTypesSupported;

    public OpenIdProviderMetadata(JsonObject providerDocument, String issuerURI, Set<String> scopesSupported, Set<String> claimsSupported, Set<String> responseTypesSupported, Set<String> idTokenSigningAlgValuesSupported, Set<String> idTokenEncryptionAlgValuesSupported, Set<String> idTokenEncryptionEncValuesSupported, Set<String> subjectTypesSupported) {
        this.document = providerDocument;
        this.issuerURI = issuerURI;
        this.scopesSupported = scopesSupported;
        this.claimsSupported = claimsSupported;
        this.responseTypesSupported = responseTypesSupported;
        this.idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported;
        this.idTokenEncryptionAlgValuesSupported = idTokenEncryptionAlgValuesSupported;
        this.idTokenEncryptionEncValuesSupported = idTokenEncryptionEncValuesSupported;
        this.subjectTypesSupported = subjectTypesSupported;
    }

    public String getIssuerURI() {
        return issuerURI;
    }

    public String getAuthorizationEndpoint() {
        return authorizationEndpoint;
    }

    public OpenIdProviderMetadata setAuthorizationEndpoint(String authorizationEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
        return this;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public OpenIdProviderMetadata setTokenEndpoint(String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
        return this;
    }

    public String getUserinfoEndpoint() {
        return userinfoEndpoint;
    }

    public OpenIdProviderMetadata setUserinfoEndpoint(String userinfoEndpoint) {
        this.userinfoEndpoint = userinfoEndpoint;
        return this;
    }

    public String getEndSessionEndpoint() {
        return endSessionEndpoint;
    }

    public OpenIdProviderMetadata setEndSessionEndpoint(String endSessionEndpoint) {
        this.endSessionEndpoint = endSessionEndpoint;
        return this;
    }

    public URL getJwksURL() {
        return jwksURL;
    }

    public OpenIdProviderMetadata setJwksURL(URL jwksURL) {
        this.jwksURL = jwksURL;
        return this;
    }

    public JsonObject getDocument() {
        return document;
    }

    public OpenIdProviderMetadata setDocument(JsonObject document) {
        this.document = document;
        return this;
    }

    public Set<String> getScopesSupported() {
        return scopesSupported;
    }

    public Set<String> getClaimsSupported() {
        return claimsSupported;
    }

    public Set<String> getResponseTypesSupported() {
        return responseTypesSupported;
    }

    public Set<String> getSubjectTypesSupported() {
        return subjectTypesSupported;
    }

    public Set<String> getIdTokenSigningAlgValuesSupported() {
        return idTokenSigningAlgValuesSupported;
    }

    public Set<String> getIdTokenEncryptionAlgValuesSupported() {
        return idTokenEncryptionAlgValuesSupported;
    }

    public Set<String> getIdTokenEncryptionEncValuesSupported() {
        return idTokenEncryptionEncValuesSupported;
    }

    @Override
    public String toString() {
        return OpenIdProviderMetadata.class.getSimpleName()
                + "{"
                + "issuerURI=" + issuerURI
                + ", authorizationEndpoint=" + authorizationEndpoint
                + ", tokenEndpoint=" + tokenEndpoint
                + ", userinfoEndpoint=" + userinfoEndpoint
                + ", jwksURI=" + jwksURL
                + '}';
    }

}
