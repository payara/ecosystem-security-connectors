/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) [2021] Payara Foundation and/or its affiliates. All rights reserved.
 *
 * The contents of this file are subject to the terms of either the GNU
 * General Public License Version 2 only ("GPL") or the Common Development
 * and Distribution License("CDDL") (collectively, the "License").  You
 * may not use this file except in compliance with the License.  You can
 * obtain a copy of the License at
 * https://github.com/payara/Payara/blob/master/LICENSE.txt
 * See the License for the specific
 * language governing permissions and limitations under the License.
 *
 * When distributing the software, include this License Header Notice in each
 * file and include the License file at glassfish/legal/LICENSE.txt.
 *
 * GPL Classpath Exception:
 * The Payara Foundation designates this particular file as subject to the "Classpath"
 * exception as provided by the Payara Foundation in the GPL Version 2 section of the License
 * file that accompanied this code.
 *
 * Modifications:
 * If applicable, add the following below the License Header, with the fields
 * enclosed by brackets [] replaced by your own identifying information:
 * "Portions Copyright [year] [name of copyright owner]"
 *
 * Contributor(s):
 * If you wish your version of this file to be governed by only the CDDL or
 * only the GPL Version 2, indicate your decision by adding "[Contributor]
 * elects to include this software in this distribution under the [CDDL or GPL
 * Version 2] license."  If you don't indicate a single choice of license, a
 * recipient has the option to distribute your version of this file under
 * either the CDDL, the GPL Version 2 or to extend the choice of license to
 * its licensees as provided above.  However, if you add GPL Version 2 code
 * and therefore, elected the GPL Version 2 license, then the option applies
 * only if the new code is made subject to such option by the copyright
 * holder.
 */
package fish.payara.security.openid.domain;

import fish.payara.security.openid.api.AccessToken;
import fish.payara.security.openid.api.OpenIdConstant;
import fish.payara.security.openid.controller.UserInfoController;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.json.Json;
import javax.json.JsonObject;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@RunWith(JUnitPlatform.class)
public class OpenIdContextImplTest {

    @Mock
    private OpenIdConfiguration configuration;

    @Mock
    private AccessToken accessToken;

    @Mock
    private UserInfoController userInfoController;

    @Spy
    @InjectMocks
    private OpenIdContextImpl openIdContext;

    @Test
    public void skipUserInfoEndpointTest() {
        JsonObject userInfo = Json.createObjectBuilder()
                .add(OpenIdConstant.SUBJECT_IDENTIFIER, "LXx-wZ96RrwuRaJs2qcenyHj_FgYSujqLikXMbEvQYE")
                .add(OpenIdConstant.NAME, "Jason Smith")
                .add(OpenIdConstant.FAMILY_NAME, "Smith")
                .add(OpenIdConstant.GIVEN_NAME, "Jason")
                .add(OpenIdConstant.EMAIL, "jason.smith@payara.fish").build();
        when(configuration.isUserClaimsFromIDToken()).thenReturn(true);
        doReturn(userInfo).when(openIdContext).processUserClaimsFromIDToken();

        JsonObject claims = openIdContext.getClaimsJson();

        Assertions.assertNotNull(claims);
        verify(configuration, times(1)).isUserClaimsFromIDToken();
        verify(openIdContext, times(1)).processUserClaimsFromIDToken();
        verify(userInfoController, times(0)).getUserInfo(configuration, accessToken);
    }

    @Test
    public void skipUserInfoEndpointThrowsExceptionTest() {
        JsonObject claims = null;
        when(configuration.isUserClaimsFromIDToken()).thenReturn(true);
        doThrow(new IllegalStateException("UserInfo Response is invalid"))
                .when(openIdContext).processUserClaimsFromIDToken();
        try {
            claims = openIdContext.getClaimsJson();
            Assertions.fail("this is not expected to be executed");
        } catch (IllegalStateException e) {
            //UserInfo Response is invalid as sub claim must match with the sub Claim in the ID Token
        }
        verify(configuration, times(1)).isUserClaimsFromIDToken();
        verify(openIdContext, times(1)).processUserClaimsFromIDToken();
        verify(userInfoController, times(0)).getUserInfo(configuration, accessToken);
    }

}