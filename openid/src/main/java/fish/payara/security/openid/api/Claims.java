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

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.OptionalDouble;
import java.util.OptionalInt;
import java.util.OptionalLong;

public interface Claims {
    /**
     * Get String claim of given name
     *
     * @param name
     * @return value, or empty optional if not present
     * @throws IllegalArgumentException when value of claim is not a string
     */
    Optional<String> getStringClaim(String name);

    /**
     * Get Numeric Date claim of given name
     *
     * @param name
     * @return value, or empty optional if not present
     * @throws IllegalArgumentException when value of claim is not a number that represents an epoch seconds
     */
    Optional<Instant> getNumericDateClaim(String name);

    /**
     * Get String List claim of given name
     *
     * @param name
     * @return a list with values of the claim, or empty list if value is not present.
     * @throws IllegalArgumentException when value of claim is neither string or array of strings
     */
    List<String> getArrayStringClaim(String name);

    /**
     * Get integer claim of given name
     *
     * @param name
     * @return value, or empty optional if not present
     * @throws IllegalArgumentException when value of claim is not a number
     */
    OptionalInt getIntClaim(String name);

    /**
     * Get long claim of given name
     *
     * @param name
     * @return value, or empty optional if not present
     * @throws IllegalArgumentException when value of claim is not a number
     */
    OptionalLong getLongClaim(String name);

    /**
     * Get double claim of given name
     *
     * @param name
     * @return value, or empty optional if not present
     * @throws IllegalArgumentException when value of claim is not a number
     */
    OptionalDouble getDoubleClaim(String name);

    /**
     * Get nested claims of given name.
     * @param name
     * @return Claims instance represented nested values within that claim, or empty optional if not present
     * @throws IllegalArgumentException when value is not a nested object
     */
    Optional<Claims> getNested(String name);
}
