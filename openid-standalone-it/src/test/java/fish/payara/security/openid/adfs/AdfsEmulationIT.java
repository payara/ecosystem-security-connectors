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

import java.io.IOException;
import java.net.URI;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.Response;

import fish.payara.arquillian.jersey.client.ClientProperties;
import fish.payara.security.openid.idp.LogExceptionOnServerSide;
import fish.payara.security.openid.idp.NaiveCookieManager;
import fish.payara.security.openid.idp.OpenIdDeployment;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit5.ArquillianExtension;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(ArquillianExtension.class)
@ExtendWith(LogExceptionOnServerSide.class)
public class AdfsEmulationIT {
    @Deployment
    public static WebArchive deployment() {
        return OpenIdDeployment.withAbstractProvider().addClasses(JaxrsApplication.class, AdfsEmulation.class, AdfsAuth.class,
                AccessTokenRoleMapping.class, UrlExtractor.class, OpenIdCallback.class, NaiveCookieManager.class);
    }

    @ArquillianResource
    URI baseUri;

    @Test
    public void accessTokenGetsAccepted() throws IOException {
        Client client = ClientBuilder.newClient();
        WebTarget base = client.target(baseUri);
        JsonObject token = base.path("idp/token").request().post(Entity.form(new Form().param("grant_type", "gimme")),
                JsonObject.class);
        String accessToken = token.getString("access_token");
        String myself = base.path("client").request().header("Authorization", "Bearer " + accessToken).get(String.class);
        assertEquals("test_subject", myself);
    }

    @Test
    public void userInfoEndpointIsNotTouched() {
        Client client = ClientBuilder.newClient().register(new NaiveCookieManager()).property(ClientProperties.FOLLOW_REDIRECTS, false);

        WebTarget base = client.target(baseUri);
        // this request redirects takes client to code authorization endpoint, and gets redirected to openid callback
        // we need to manually follow these redirects otherwise our naive cookie manager will not collect relevant cookies
        // to identify ourselves when we land back at callback

        // client redirects us to idp code
        Response response = base.path("client").request().get();
        assertEquals(Response.Status.Family.REDIRECTION, response.getStatusInfo().getFamily());

        // code redirects to OAuth callback
        response = client.target(response.getLocation()).request().get();
        assertEquals(Response.Status.Family.REDIRECTION, response.getStatusInfo().getFamily());

        // oauth callback returns list of groups for us
        response = client.target(response.getLocation()).request().get();
        JsonArray groups = response.readEntity(JsonArray.class);
        assertEquals(Json.createArrayBuilder().add("authenticated").add("code_exchange").build(), groups);
    }
}
