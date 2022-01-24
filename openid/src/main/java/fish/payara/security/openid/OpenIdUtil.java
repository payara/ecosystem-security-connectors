/*
 * Copyright (c) [2020-2021] Payara Foundation and/or its affiliates. All rights reserved.
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
package fish.payara.security.openid;

import java.util.Arrays;
import java.util.HashSet;
import static java.util.Objects.isNull;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import jakarta.el.ELProcessor;
import jakarta.enterprise.inject.spi.BeanManager;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;
import jakarta.json.JsonNumber;
import static jakarta.json.JsonValue.ValueType.STRING;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import org.eclipse.microprofile.config.Config;

/**
 * Utility class for evaluation of OpenId values.
 *
 * @author Gaurav Gupta
 * @author Petr Aubrecht
 */
public final class OpenIdUtil {

    private OpenIdUtil() {
    }

    public static String readConfiguredValueFromMetadataOrProvider(String metadataValue, JsonObject providerDocument, String openIdConstant, Config provider, String openIdProviderMetadataName) {
        String value;
        if (isEmpty(metadataValue) && providerDocument.containsKey(openIdConstant)) {
            value = getConfiguredValue(String.class, providerDocument.getString(openIdConstant), provider, openIdProviderMetadataName);
        } else {
            value = getConfiguredValue(String.class, metadataValue, provider, openIdProviderMetadataName);
        }
        return value;
    }

    public static Set<String> readConfiguredValueFromMetadataOrProvider(String[] metadataValue, JsonObject providerDocument, String openIdConstant, Config provider, String openIdProviderMetadataName) {
        String[] valueArr;
        if (metadataValue.length == 0 && providerDocument.containsKey(openIdConstant)) {
            valueArr = getConfiguredValue(String[].class, getValues(providerDocument, openIdConstant), provider, openIdProviderMetadataName);
        } else {
            valueArr = getConfiguredValue(String[].class, metadataValue, provider, openIdProviderMetadataName);
        }
        return new HashSet<>(Arrays.asList(valueArr));
    }

    private static String[] getValues(JsonObject document, String key) {
        JsonArray jsonArray = document.getJsonArray(key);
        if (isNull(jsonArray)) {
            return new String[]{};
        } else {
            return jsonArray
                    .stream()
                    .filter(element -> element.getValueType() == STRING)
                    .map(element -> (JsonString) element)
                    .map(JsonString::getString)
                    .toArray(String[]::new);
        }
    }

    public static <T> T getConfiguredValue(Class<T> type, T value, Config provider, String mpConfigKey) {
        T result = value;
        Optional<T> configResult = provider.getOptionalValue(mpConfigKey, type);
        if (configResult.isPresent()) {
            return configResult.get();
        }
        if (type == String.class && isELExpression((String) value)) {
            ELProcessor elProcessor = new ELProcessor();
            BeanManager beanManager = getBeanManagerForCurrentModule();
            elProcessor.getELManager().addELResolver(beanManager.getELResolver());
            result = (T) elProcessor.getValue(toRawExpression((String) result), type);
        }
        return result;
    }

    private static BeanManager getBeanManagerForCurrentModule() {
        /*
         For some reason, CDI.current().getBeanManager() doesn't always return
         the correct bean manager in EAR, therefore we're using JNDI lookup until this is fixed.
         See https://lists.jboss.org/pipermail/cdi-dev/2016-April/008185.html
         */
        try {
            return (BeanManager) new InitialContext().lookup("java:comp/BeanManager");
        } catch (NamingException ex) {
            throw new RuntimeException(ex);
        }
    }

    public static boolean isELExpression(String expression) {
        return expression != null && !expression.isEmpty() && isDeferredExpression(expression);
    }

    public static boolean isDeferredExpression(String expression) {
        return expression.startsWith("#{") && expression.endsWith("}");
    }

    public static String toRawExpression(String expression) {
        return expression.substring(2, expression.length() - 1);
    }

    public static <T> Predicate<T> not(Predicate<T> t) {
        return t.negate();
    }

    /**
     * Checks if a string is null or empty.
     *
     * @param value
     * @return <code>true</code> if the string is null or empty after trim,
     * <code>false</code> otherwirse.
     */
    public static boolean isEmpty(String value) {
        return value == null || value.trim().length() == 0;
    }

    /**
     * Parse a JSON value as long even if it is provided as a string.
     *
     * @param json json object
     * @param fieldName name of the field (key)
     * @return long representation of the field
     */
    public static Long parseLong(JsonObject json, String fieldName) {
        Long longField = null;
        JsonValue jsonField = json.get(fieldName);
        if (jsonField instanceof JsonNumber) {
            longField = ((JsonNumber) jsonField).longValue();
        } else if (jsonField instanceof JsonString) {
            // Microsoft Azure AD B2C returns expires_in value as a string
            longField = Long.valueOf(((JsonString) jsonField).getString());
        }
        return longField;
    }
}
