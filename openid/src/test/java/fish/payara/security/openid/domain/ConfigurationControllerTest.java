/*
 * Copyright (c) 2021 Payara Foundation and/or its affiliates. All rights reserved.
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

import fish.payara.security.openid.OpenIdAuthenticationException;
import fish.payara.security.openid.controller.ConfigurationController;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/**
 * Test ConfigurationController.
 *
 * @author Petr Aubrecht <petr@aubrecht.net>
 */
@RunWith(JUnitPlatform.class)
public class ConfigurationControllerTest {

    @Test
    public void createUrlNoParameter() {
        assertEquals("",
                ConfigurationController.createUrlQuery("extraParameters", new String[]{}));
    }

    @Test
    public void createUrlOneParameter() {
        assertEquals("a=b",
                ConfigurationController.createUrlQuery("extraParameters", new String[]{"a=b"}));
    }

    @Test
    public void createUrlSimpleParameters() {
        assertEquals("a=b&c=d",
                ConfigurationController.createUrlQuery("extraParameters", new String[]{"a=b", "c=d"}));
    }

    @Test
    public void createUrlNoValueParameters() {
        assertEquals("a&c=d&e",
                ConfigurationController.createUrlQuery("extraParameters", new String[]{"a", "c=d", "e"}));
    }

    @Test
    public void createUrlWithSpacesParameters() {
        assertEquals("a=b+b&c=++d++&e",
                ConfigurationController.createUrlQuery("extraParameters", new String[]{"a=b b", "c=  d  ", "e="}));
    }

    @Test
    public void createUrlWithoutKeyNameParameters() {
        // these cases are cought by OpenIdExtension anyway, just defensive test:
        Assertions.assertThrows(OpenIdAuthenticationException.class,
                () -> ConfigurationController.createUrlQuery("extraParameters", new String[]{""}));
        Assertions.assertThrows(OpenIdAuthenticationException.class,
                () -> ConfigurationController.createUrlQuery("extraParameters", new String[]{"="}));
        Assertions.assertThrows(OpenIdAuthenticationException.class,
                () -> ConfigurationController.createUrlQuery("extraParameters", new String[]{"=a"}));
    }

    @Test
    public void createUrlWithBlankKeyNameParameters() {
        assertEquals("+=+",
                ConfigurationController.createUrlQuery("extraParameters", new String[]{" = "}));
    }

    @Test
    public void parseMultiMapFromUrlQuery() {
        Map<String, List<String>> result = new HashMap<>();
        result.put("a", Arrays.asList("b"));
        assertEquals(result, ConfigurationController.parseMultiMapFromUrlQuery("a=b"));
    }

    @Test
    public void parseMultiMapFromUrlQueryNoValue() {
        Map<String, List<String>> result = new HashMap<>();
        result.put("a", Arrays.asList((String) null));
        assertEquals(result, ConfigurationController.parseMultiMapFromUrlQuery("a="));
    }

    @Test
    public void parseMultiMapFromUrlQueryNoValueWithoutEquals() {
        Map<String, List<String>> result = new HashMap<>();
        result.put("a", Arrays.asList((String) null));
        assertEquals(result, ConfigurationController.parseMultiMapFromUrlQuery("a"));
    }

    @Test
    public void parseMultiMapFromUrlQueryMultipleValues() {
        Map<String, List<String>> result = new HashMap<>();
        result.put("a", Arrays.asList("b", "c"));
        assertEquals(result, ConfigurationController.parseMultiMapFromUrlQuery("a=b&a=c"));
    }

    @Test
    public void parseMultiMapFromUrlQueryMultipleKeysMultipleValues() {
        Map<String, List<String>> result = new HashMap<>();
        result.put("a", Arrays.asList("b", "c"));
        result.put("x", Arrays.asList("y", "z"));
        assertEquals(result, ConfigurationController.parseMultiMapFromUrlQuery("a=b&a=c&x=y&x=z"));
    }

    @Test
    public void parseMultiMapFromUrlQueryMultipleKeysWithSpaces() {
        Map<String, List<String>> result = new HashMap<>();
        result.put("a", Arrays.asList("b b"));
        result.put("c", Arrays.asList("  d  "));
        result.put("e", Arrays.asList((String) null));
        assertEquals(result, ConfigurationController.parseMultiMapFromUrlQuery("a=b+b&c=++d++&e"));
    }
}
