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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

import com.nimbusds.jwt.JWTClaimsSet;
import fish.payara.security.openid.api.JwtClaims;
import fish.payara.security.openid.api.OpenIdConstant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class NimbusJwtClaimsTest {
    private JwtClaims cut;

    @Nested
    @DisplayName("getStringClaim")
    class StringClaimTest {
        @Test
        public void notExistingReturnsEmpty() {
            assumeClaims(b -> b);
            assertEmpty(cut.getStringClaim("any"));
        }

        @Test
        public void notStringThrows() {
            assumeClaims(b -> b.claim("any", 1));
            assertThrows(IllegalArgumentException.class, () -> cut.getStringClaim("any"));
        }

        @Test
        public void existingStringPresent() {
            assumeClaims(b -> b.issuer("me"));
            assertPresentAndEqual(cut.getIssuer(), "me");
        }
    }

    @Nested
    @DisplayName("getNumberDateClaim")
    class NumericDateClaimTest {
        @Test
        public void notExistingReturnsEmpty() {
            assumeClaims(b -> b);
            assertEmpty(cut.getNumericDateClaim("any"));
        }

        @Test
        public void notNumberThrows() {
            assumeClaims(b -> b.claim("any", "a"));
            assertThrows(IllegalArgumentException.class, () -> cut.getNumericDateClaim("any"));
        }

        @Test
        public void existingNumberPresent() {
            OffsetDateTime referenceDate = OffsetDateTime.of(LocalDate.of(2021, 2, 3), LocalTime.of(14, 16), ZoneOffset.UTC);
            assumeClaims(b -> b.claim("date", referenceDate.toEpochSecond()));
            assertPresentAndEqual(cut.getNumericDateClaim("date"), referenceDate.toInstant());
        }
    }

    @Nested
    @DisplayName("isExpired")
    class ExpirationTest {
        Duration skew = Duration.ofMinutes(1);


        @Test
        public void nonExistingNotRequired() {
            assumeClaims(b -> b);
            assertFalse(cut.isExpired(Clock.systemUTC(), false, skew), "When not required and expiration not present, should not be expired");
        }

        @Test
        public void nonExistingRequired() {
            assumeClaims(b -> b);
            assertTrue(cut.isExpired(Clock.systemUTC(), true, skew), "When required and expiration not present, should be expired");
        }

        @Test
        public void beforeExpiration() {
            Instant expirationTime = Instant.parse("2021-03-02T14:50:00Z");
            assumeClaims(b -> b.claim(OpenIdConstant.EXPIRATION_IDENTIFIER, expirationTime.getEpochSecond()));

            Instant testTime = Instant.parse("2021-03-02T14:23:00Z");
            assertFalse(cut.isExpired(Clock.fixed(testTime, ZoneOffset.UTC), true, skew), "When before expiration time, should not be expired");
        }

        @Test
        public void withinSkew() {
            Instant expirationTime = Instant.parse("2021-03-02T14:50:00Z");
            assumeClaims(b -> b.claim(OpenIdConstant.EXPIRATION_IDENTIFIER, expirationTime.getEpochSecond()));

            Instant testTime = Instant.parse("2021-03-02T14:50:59.999Z");
            assertFalse(cut.isExpired(Clock.fixed(testTime, ZoneOffset.UTC), true, skew), "When within clock skew, should not be expired");
        }

        @Test
        public void expired() {
            Instant expirationTime = Instant.parse("2021-03-02T14:50:00Z");
            assumeClaims(b -> b.claim(OpenIdConstant.EXPIRATION_IDENTIFIER, expirationTime.getEpochSecond()));

            Instant testTime = Instant.parse("2021-03-02T14:51:01Z");
            assertTrue(cut.isExpired(Clock.fixed(testTime, ZoneOffset.UTC), true, skew), "When outside clock skew, should be expired");
        }
    }

    @Nested
    @DisplayName("isBeforeValidity")
    class BeforeValidityTest {
        Duration skew = Duration.ofMinutes(1);


        @Test
        public void nonExistingNotRequired() {
            assumeClaims(b -> b);
            assertFalse(cut.isBeforeValidity(Clock.systemUTC(), false, skew), "When not required and nbf not present, should not be before validity");
        }

        @Test
        public void nonExistingRequired() {
            assumeClaims(b -> b);
            assertTrue(cut.isBeforeValidity(Clock.systemUTC(), true, skew), "When required and nbf not present, should be before validity");
        }

        @Test
        public void afterValidity() {
            Instant initiationTime = Instant.parse("2021-03-02T14:23:00Z");
            assumeClaims(b -> b.claim("nbf", initiationTime.getEpochSecond()));

            Instant testTime = Instant.parse("2021-03-02T14:50:00Z");
            assertFalse(cut.isBeforeValidity(Clock.fixed(testTime, ZoneOffset.UTC), true, skew), "When after nbf time, should not be before validity");
        }

        @Test
        public void withinSkew() {
            Instant initiationTime = Instant.parse("2021-03-02T14:23:00Z");
            assumeClaims(b -> b.claim("nbf", initiationTime.getEpochSecond()));

            Instant testTime = Instant.parse("2021-03-02T14:22:00.001Z");
            assertFalse(cut.isBeforeValidity(Clock.fixed(testTime, ZoneOffset.UTC), true, skew), "When within clock skew, should not be before validity");
        }

        @Test
        public void beforeValidity() {
            Instant initiationTime = Instant.parse("2021-03-02T14:50:00Z");
            assumeClaims(b -> b.claim(OpenIdConstant.EXPIRATION_IDENTIFIER, initiationTime.getEpochSecond()));

            Instant testTime = Instant.parse("2021-03-02T14:23:00Z");
            assertTrue(cut.isBeforeValidity(Clock.fixed(testTime, ZoneOffset.UTC), true, skew), "When before validity, then it really should be");
        }
    }

    @Nested
    @DisplayName("getAudience")
    class AudienceTest {
        @Test
        public void notExistingReturnsEmpty() {
            assumeClaims(b -> b);
            assertTrue(cut.getAudience().isEmpty());
        }

        @Test
        public void notStringThrows() {
            assumeClaims(b -> b.claim(OpenIdConstant.AUDIENCE, 1));
            assertThrows(IllegalArgumentException.class, () -> cut.getAudience());
        }

        @Test
        public void singleValueIsSingletonList() {
            assumeClaims(b -> b.audience("a"));
            assertEquals(Collections.singletonList("a"), cut.getAudience());
        }

        @Test
        public void multiValueIsList() {
            assumeClaims(b -> b.audience(Arrays.asList("a", "b")));
            assertEquals(Arrays.asList("a", "b"), cut.getAudience());
        }
    }

    @Test
    public void returnsEmptyOnNullClaims() {
        this.cut = NimbusJwtClaims.ifPresent(null);
        assertEmpty(cut.getStringClaim("any"));
        assertEmpty(cut.getIssuer());
        assertEmpty(cut.getSubject());
        assertEmpty(cut.getAudience());
        assertEmpty(cut.getExpirationTime());
        assertEmpty(cut.getJwtId());
        assertEmpty(cut.getIssuedAt());
        assertEmpty(cut.getNotBeforeTime());
        assertEmpty(cut.getNumericDateClaim("any"));
        assertFalse(cut.getIntClaim("any").isPresent(), "Value should not be present");
        assertFalse(cut.getLongClaim("any").isPresent(), "Value should not be present");
        assertFalse(cut.getDoubleClaim("any").isPresent(), "Value should not be present");
    }

    static <T> void  assertPresentAndEqual(Optional<T> optional, T value) {
        assertPresent(optional);
        assertEquals(value, optional.get());
    }


    static void assertEmpty(List<String> list) {
        assertTrue(list.isEmpty(), "Value should not be present");
    }

    static JWTClaimsSet.Builder builder() {
        return new JWTClaimsSet.Builder();
    }

    JwtClaims assumeClaims(Function<JWTClaimsSet.Builder, JWTClaimsSet.Builder> buildup) {
        this.cut = NimbusJwtClaims.ifPresent(buildup.apply(builder()).build());
        return cut;
    }

    static void assertPresent(Optional<?> opt) {
        assertTrue(opt.isPresent(), "Value should be present");
    }

    static void assertEmpty(Optional<?> opt) {
        assertFalse(opt.isPresent(), "Value should not be present");
    }
}
