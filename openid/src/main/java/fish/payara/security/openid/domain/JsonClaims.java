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

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.OptionalDouble;
import java.util.OptionalInt;
import java.util.OptionalLong;
import java.util.stream.Collectors;

import javax.json.JsonNumber;
import javax.json.JsonObject;
import javax.json.JsonValue;

import fish.payara.security.openid.api.Claims;
import fish.payara.security.openid.api.OpenIdClaims;
import javax.json.JsonString;

class JsonClaims implements OpenIdClaims {
    private final JsonObject claims;

    JsonClaims(JsonObject claims) {
        this.claims = claims;
    }

    @Override
    public Optional<String> getStringClaim(String name) {
        return Optional.ofNullable(claims.getString(name, null));
    }

    @Override
    public Optional<Instant> getNumericDateClaim(String name) {
        return Optional.ofNullable(getNumber(name))
                .map(n -> Instant.ofEpochSecond(n.longValue()));
    }

    @Override
    public List<String> getArrayStringClaim(String name) {
        JsonValue value = claims.get(name);
        if (value == null) {
            return Collections.emptyList();
        }
        if (value.getValueType() == JsonValue.ValueType.ARRAY) {
            return value.asJsonArray().stream().map(this::getStringValue).collect(Collectors.toList());
        }
        return Collections.singletonList(getStringValue(value));
    }

    private String getStringValue(JsonValue value) {
        switch (value.getValueType()) {
            case STRING:
                return ((JsonString)value).getString();
            case TRUE:
                return "true";
            case FALSE:
                return "false";
            case NUMBER:
                return ((JsonNumber)value).numberValue().toString();
            default:
                throw new IllegalArgumentException("Cannot handle nested JSON value in a claim:" + value);
        }
    }
    
    private JsonNumber getNumber(String name) {
        try {
            return claims.getJsonNumber(name);
        } catch (ClassCastException cce) {
            throw new IllegalArgumentException("Cannot interpret "+name+" as number", cce);
        }
    }

    @Override
    public OptionalInt getIntClaim(String name) {
        JsonNumber value = getNumber(name);
        return value == null ? OptionalInt.empty() : OptionalInt.of(value.intValue());
    }

    @Override
    public OptionalLong getLongClaim(String name) {
        JsonNumber value = getNumber(name);
        return value == null ? OptionalLong.empty() : OptionalLong.of(value.longValue());
    }

    @Override
    public OptionalDouble getDoubleClaim(String name) {
        JsonNumber value = getNumber(name);
        return value == null ? OptionalDouble.empty() : OptionalDouble.of(value.doubleValue());
    }

    @Override
    public Optional<Claims> getNested(String claimName) {
        return Optional.ofNullable(claims.getJsonObject(claimName)).map(JsonClaims::new);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
                + "{"
                + "subject=" + getSubject()
                + ",name=" + getName()
                + ", familyName=" + getFamilyName()
                + ", givenName=" + getGivenName()
                + ", middleName=" + getMiddleName()
                + ", nickname=" + getNickname()
                + ", preferredUsername=" + getPreferredUsername()
                + ", profile=" + getProfile()
                + ", picture=" + getPicture()
                + ", website=" + getWebsite()
                + ", gender=" + getGender()
                + ", birthdate=" + getBirthdate()
                + ", zoneinfo=" + getZoneinfo()
                + ", locale=" + getLocale()
                + ", updatedAt=" + getUpdatedAt()
                + ", email=" + getEmail()
                + ", emailVerified=" + getEmailVerified()
                + ", address=" + getAddress()
                + ", phoneNumber=" + getPhoneNumber()
                + ", phoneNumberVerified=" + getPhoneNumberVerified()
                + '}';

    }
}
