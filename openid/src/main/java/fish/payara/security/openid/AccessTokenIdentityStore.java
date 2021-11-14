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

package fish.payara.security.openid;

import java.text.ParseException;
import java.util.Collections;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.ContextNotActiveException;
import javax.enterprise.context.SessionScoped;
import javax.enterprise.inject.Typed;
import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStore;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import fish.payara.security.openid.api.AccessTokenCallerPrincipal;
import fish.payara.security.openid.api.AccessTokenCredential;
import fish.payara.security.openid.controller.JWTValidator;
import fish.payara.security.openid.controller.TokenClaimsSetVerifier;
import fish.payara.security.openid.domain.AccessTokenImpl;
import fish.payara.security.openid.domain.OpenIdConfiguration;
import fish.payara.security.openid.domain.OpenIdContextImpl;

@ApplicationScoped
@Typed(AccessTokenIdentityStore.class)
public class AccessTokenIdentityStore implements IdentityStore {
    private static final Logger LOGGER = Logger.getLogger(AccessTokenIdentityStore.class.getName());
    @Inject
    OpenIdContextImpl context;
    @Inject
    OpenIdConfiguration configuration;
    @Inject
    JWTValidator validator;
    @Inject
    BeanManager beanManager;

    @Override
    public Set<ValidationType> validationTypes() {
        return Collections.singleton(ValidationType.VALIDATE);
    }

    @SuppressWarnings("unused")
    public CredentialValidationResult validate(AccessTokenCredential credential) {
        try {
            AccessTokenImpl accessToken = AccessTokenImpl.forBearerToken(configuration,
                    credential.getAccessToken(),
                    new BearerVerifier(configuration), validator);

            // OpenIdContext is session scoped, but access tokens might be validated outside of HTTP session
            if (isSessionActive()) {
                context.setAccessToken(accessToken);
                // for setClaims we'd need to invoke userinfo. That should be lazy unless required
                context.setCallerName(
                        // use configured caller name claim if present in access token
                        accessToken.getJwtClaims().getStringClaim(
                                configuration.getClaimsConfiguration().getCallerNameClaim())
                                // or subject, which is more likely present, but is still optional per JWT spec
                                .orElse(accessToken.getJwtClaims().getSubject()
                                        .orElse(null)));
            }

            return new CredentialValidationResult(new AccessTokenCallerPrincipal(accessToken, context::getClaims));
        } catch (ParseException | RuntimeException e) {
            LOGGER.log(Level.WARNING, "Cannot parse access token " + credential.getAccessToken(), e);
        }
        return CredentialValidationResult.INVALID_RESULT;
    }

    private boolean isSessionActive() {
        try {
            return beanManager.getContext(SessionScoped.class).isActive();
        } catch (ContextNotActiveException notActive) {
            return false;
        }
    }

    static class BearerVerifier extends TokenClaimsSetVerifier {
        public BearerVerifier(OpenIdConfiguration configuration) {
            super(configuration);
        }

        @Override
        public void verify(JWTClaimsSet claims, SecurityContext c) throws BadJWTException {
            StandardVerifications standardVerifications = new StandardVerifications(configuration, claims);

            standardVerifications.requireSameIssuer();
            standardVerifications.requireSubject();
            standardVerifications.requireValidTimestamp();
            // Validating audience is left to application now. We generally expect that we'll accept the token from
            // issuer, worst case no groups will be assigned
        }

        @Override
        public void verify(JWTClaimsSet jwtcs) throws BadJWTException {

        }
    }
}
