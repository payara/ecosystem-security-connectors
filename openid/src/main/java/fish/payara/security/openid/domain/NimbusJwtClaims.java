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

import java.text.ParseException;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.OptionalDouble;
import java.util.OptionalInt;
import java.util.OptionalLong;

import com.nimbusds.jwt.JWTClaimsSet;
import fish.payara.security.openid.api.JwtClaims;

class NimbusJwtClaims implements JwtClaims {
    private final JWTClaimsSet claimsSet;

    NimbusJwtClaims(JWTClaimsSet claimsSet) {
        this.claimsSet = claimsSet;
    }

    @Override
    public Optional<String> getStringClaim(String name) {
        try {
            return Optional.ofNullable(claimsSet.getStringClaim(name));
        } catch (ParseException e) {
            throw new IllegalArgumentException("Cannot parse "+name+" as string", e);
        }
    }

    @Override
    public Optional<Instant> getNumericDateClaim(String name) {
        try {
            return Optional.ofNullable(claimsSet.getDateClaim(name)).map(Date::toInstant);
        } catch (ParseException e) {
            throw new IllegalArgumentException("Cannot parse "+name+" as numeric date", e);
        }
    }

    @Override
    public List<String> getArrayStringClaim(String name) {
        Object audValue = claimsSet.getClaim(name);
        if (audValue == null) {
            return Collections.emptyList();
        }
        if (audValue instanceof String) {
            return Collections.singletonList((String)audValue);
        }
        List<String> aud;
        try {
            return claimsSet.getStringListClaim(name);
        } catch (ParseException e) {
            throw new IllegalArgumentException("Cannot parse "+name+" as a string array", e);
        }
    }

    @Override
    public OptionalInt getIntClaim(String name) {
        Integer value = null;
        try {
            value = claimsSet.getIntegerClaim(name);
        } catch (ParseException e) {
            throw new IllegalArgumentException("Cannot parse "+name+" as number");
        }
        return value == null ? OptionalInt.empty() : OptionalInt.of(value);
    }

    @Override
    public OptionalLong getLongClaim(String name) {
        Long value = null;
        try {
            value = claimsSet.getLongClaim(name);
        } catch (ParseException e) {
            throw new IllegalArgumentException("Cannot parse "+name+" as number");
        }
        return value == null ? OptionalLong.empty() : OptionalLong.of(value);
    }

    @Override
    public OptionalDouble getDoubleClaim(String name) {
        Double value = null;
        try {
            value = claimsSet.getDoubleClaim(name);
        } catch (ParseException e) {
            throw new IllegalArgumentException("Cannot parse "+name+" as number");
        }
        return value == null ? OptionalDouble.empty() : OptionalDouble.of(value);
    }

    @Override
    public String toString() {
        return claimsSet.toString();
    }

    static JwtClaims ifPresent(JWTClaimsSet claimsSet) {
        return claimsSet == null ? JwtClaims.NONE : new NimbusJwtClaims(claimsSet);
    }
}
