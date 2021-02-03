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

package fish.payara.security.openid.api;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.OptionalDouble;
import java.util.OptionalInt;
import java.util.OptionalLong;
import java.util.Set;

/**
 * Standard JWT claims. A token typically
 *
 *
 */
public interface JwtClaims {
    /**
     * The principal that issued the JWT
     * @return value of {@code iss} claim
     */
    default Optional<String> getIssuer() {
        return getStringClaim("iss");
    }

    /**
     * The principal that is the
     *    subject of the JWT.  The claims in a JWT are normally statements
     *    about the subject.
     * @return value of {@code sub} claim
     */
    default Optional<String> getSubject() {
        return getStringClaim("sub");
    }

    /**
     * The recipients that the JWT is intended for. To ease work with the field, audience is always represented as list,
     * also in special cases -- it is singleton list when it was a string in the token, and empty set if it was not present.
     * @return non-null set representing the values of {@code aud} claim
     */
    default List<String> getAudience() {
        return getArrayStringClaim("aud");
    }

    /**
     * Expiration time on or after which the JWT MUST NOT be accepted for processing.
     * @return value of {@code exp} claim
     */
    default Optional<Instant> getExpirationTime() {
        return getNumericDateClaim("exp");
    }

    /**
     * Check if JWT is expired
     * @param clock Clock representing reference time of checking
     * @param required indication whether the claim is required, i. e. whether token with claim is considered expired
     * @param skew allowed clock skew to account for drift between provider and us
     * @return {@code} true when current time is past expiration time, or {@code exp} claim is not present and {@code required} is {@code true}
     */
    default boolean isExpired(Clock clock, boolean required, Duration skew) {
        return getExpirationTime().map(exp -> clock.millis() - exp.toEpochMilli() > skew.toMillis())
                .orElse(required);
    }

    /**
     * The time before which the JWT MUST NOT be accepted for processing.
     * @return
     */
    default Optional<Instant> getNotBeforeTime() {
        return getNumericDateClaim("nbf");
    }

    /**
     * Check if JWT is before its defined validity
     * @param clock Clock representing reference time of checking
     * @param required indication, whether the claim is required, i. e. whether token without nbf is considered before validity
     * @param skew allowed clock skew to account for drift between provider and us
     * @return
     */
    default boolean isBeforeValidity(Clock clock, boolean required, Duration skew) {
        return getNotBeforeTime().map(nbf -> nbf.toEpochMilli() - clock.millis() > skew.toMillis())
                .orElse(required);
    }

    /**
     * Check JWT validity against current time with 1MIN clock skew.
     * @return true if exp token is present and within limits and nbf is within limits when present
     */
    default boolean isValid() {
        Duration skew = Duration.ofMinutes(1);
        return !isExpired(Clock.systemUTC(), true, skew) && !isBeforeValidity(Clock.systemUTC(), false, skew);
    }

    /**
     * The time at which the JWT was issued.
     * @return value of {@code exp} claim
     */
    default Optional<Instant> getIssuedAt() {
        return getNumericDateClaim("iat");
    }

    /**
     * Unique identifier for the JWT
     * @return value of {@code jti} claim
     */
    default Optional<String> getJwtId() {
        return getStringClaim("jti");
    }

    /**
     * Get String claim of given name
     * @param name
     * @return value, or empty optional if not present
     * @throws IllegalArgumentException when value of claim is not a string
     */
    Optional<String> getStringClaim(String name);

    /**
     * Get Numeric Date claim of given name
     * @param name
     * @return value, or empty optional if not present
     * @throws IllegalArgumentException when value of claim is not a number that represents an epoch seconds
     */
    Optional<Instant> getNumericDateClaim(String name);

    /**
     * Get String List claim of given name
     * @param name
     * @return a list with values of the claim, or empty list if value is not present.
     * @throws IllegalArgumentException when value of claim is neither string or array of strings
     */
    List<String> getArrayStringClaim(String name);

    /**
     * Get integer claim of given name
     * @param name
     * @return value, or empty optional if not present
     * @throws IllegalArgumentException when value of claim is not a number
     */
    OptionalInt getIntClaim(String name);

    /**
     * Get long claim of given name
     * @param name
     * @return value, or empty optional if not present
     * @throws IllegalArgumentException when value of claim is not a number
     */
    OptionalLong getLongClaim(String name);

    /**
     * Get double claim of given name
     * @param name
     * @return value, or empty optional if not present
     * @throws IllegalArgumentException when value of claim is not a number
     */
    OptionalDouble getDoubleClaim(String name);

    /**
     * Singleton instance representing no claims
     */
    JwtClaims NONE = new JwtClaims() {
        @Override
        public Optional<String> getStringClaim(String name) {
            return Optional.empty();
        }

        @Override
        public Optional<Instant> getNumericDateClaim(String name) {
            return Optional.empty();
        }

        @Override
        public List<String> getArrayStringClaim(String name) {
            return Collections.emptyList();
        }

        @Override
        public OptionalInt getIntClaim(String name) {
            return OptionalInt.empty();
        }

        @Override
        public OptionalLong getLongClaim(String name) {
            return OptionalLong.empty();
        }

        @Override
        public OptionalDouble getDoubleClaim(String name) {
            return OptionalDouble.empty();
        }
    };
}
