/*
 * Copyright (c) 2020 Payara Foundation and/or its affiliates. All rights reserved.
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

import fish.payara.security.annotations.AzureAuthenticationDefinition;
import fish.payara.security.annotations.GoogleAuthenticationDefinition;
import fish.payara.security.annotations.OpenIdAuthenticationDefinition;
import fish.payara.security.openid.controller.AuthenticationController;
import fish.payara.security.openid.controller.ConfigurationController;
import fish.payara.security.openid.controller.NonceController;
import fish.payara.security.openid.controller.ProviderMetadataContoller;
import fish.payara.security.openid.controller.StateController;
import fish.payara.security.openid.controller.TokenController;
import fish.payara.security.openid.controller.UserInfoController;
import fish.payara.security.openid.domain.OpenIdContextImpl;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.AfterBeanDiscovery;
import javax.enterprise.inject.spi.AfterTypeDiscovery;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.DefinitionException;
import javax.enterprise.inject.spi.Extension;
import javax.enterprise.inject.spi.ProcessAnnotatedType;
import javax.enterprise.inject.spi.WithAnnotations;
import java.util.logging.Logger;

import static java.util.logging.Level.INFO;

/**
 * Activates {@link OpenIdAuthenticationMechanism} with the
 * {@link OpenIdAuthenticationDefinition} annotation configuration.
 *
 * @author Gaurav Gupta
 * @author Patrik Duditš
 */
public class OpenIdExtension implements Extension {

    private static final Logger LOGGER = Logger.getLogger(OpenIdExtension.class.getName());

    private OpenIdAuthenticationDefinition definition;
    private boolean deployedAsAppLibrary;

    protected void foundMyClasses(@Observes ProcessAnnotatedType<OpenIdContextImpl> myType) {
        this.deployedAsAppLibrary = true;
    }

    /**
     * Find the {@link OpenIdAuthenticationDefinition} annotation and validate.
     */
    protected void findOpenIdDefinitionAnnotation(@Observes @WithAnnotations(OpenIdAuthenticationDefinition.class) ProcessAnnotatedType<?> event) {
        Class<?> beanClass = event.getAnnotatedType().getJavaClass();
        OpenIdAuthenticationDefinition standardDefinition = event.getAnnotatedType().getAnnotation(OpenIdAuthenticationDefinition.class);
        setDefinition(standardDefinition, beanClass, "Generic");
    }

    private void setDefinition(OpenIdAuthenticationDefinition definition, Class<?> sourceClass, String definitionKind) {
        if (this.definition != null) {
            LOGGER.warning("Multiple authentication definition found. Will ignore the definition in " + sourceClass);
            return;
        }

        this.definition = definition;
        LOGGER.log(INFO, "Activating {0} OpenID Connect authentication definition from class {1}",
                new Object[]{definitionKind, sourceClass.getName()});
    }

    /**
     * Find {@link GoogleAuthenticationDefinition} annotation and validate.
     *
     * @param event
     */
    protected void findGoogleDefinitionAnnotation(@Observes @WithAnnotations(GoogleAuthenticationDefinition.class) ProcessAnnotatedType<?> event) {
        Class<?> beanClass = event.getAnnotatedType().getJavaClass();
        OpenIdAuthenticationDefinition standardDefinition = GoogleDefinitionConverter
                .toOpenIdAuthDefinition(event.getAnnotatedType().getAnnotation(GoogleAuthenticationDefinition.class));
        setDefinition(standardDefinition, beanClass, "Google");
    }

    /**
     * Find {@link AzureAuthenticationDefinition} annotation and validate.
     *
     * @param event
     */
    protected void findAzureDefinitionAnnotation(@Observes @WithAnnotations(AzureAuthenticationDefinition.class) ProcessAnnotatedType<?> event) {
        Class<?> beanClass = event.getAnnotatedType().getJavaClass();
        OpenIdAuthenticationDefinition standardDefinition = AzureDefinitionConverter
                .toOpenIdAuthDefinition(event.getAnnotatedType().getAnnotation(AzureAuthenticationDefinition.class));
        setDefinition(standardDefinition, beanClass, "Azure");
    }

    protected void validateExtraParametersFormat(OpenIdAuthenticationDefinition definition) {
        for (String extraParameter : definition.extraParameters()) {
            String[] parts = extraParameter.split("=");
            if (parts.length != 2) {
                throw new DefinitionException(
                        OpenIdAuthenticationDefinition.class.getSimpleName()
                                + ".extraParameters() value '" + extraParameter
                                + "' is not of the format key=value"
                );
            }
        }
    }

    protected void afterTypeDiscovery(@Observes AfterTypeDiscovery afterTypeDiscovery) {
        if (!deployedAsAppLibrary) {
            registerTypes(afterTypeDiscovery);
        }
        if (this.definition != null) {
            // if there is a definition, enable mechanism and identity store
            afterTypeDiscovery.getAlternatives().add(OpenIdAuthenticationMechanism.class);
            afterTypeDiscovery.getAlternatives().add(OpenIdIdentityStore.class);
        }
    }

    protected void registerTypes(AfterTypeDiscovery event) {
        // in case this is bundled in server and not a library, the types needs explicit registration
        event.addAnnotatedType(OpenIdContextImpl.class, null);
        event.addAnnotatedType(NonceController.class, null);
        event.addAnnotatedType(StateController.class, null);
        event.addAnnotatedType(ConfigurationController.class, null);
        event.addAnnotatedType(ProviderMetadataContoller.class, null);
        event.addAnnotatedType(AuthenticationController.class, null);
        event.addAnnotatedType(TokenController.class, null);
        event.addAnnotatedType(UserInfoController.class, null);
        event.addAnnotatedType(OpenIdAuthenticationMechanism.class, null);
    }

    protected void registerDefinition(@Observes AfterBeanDiscovery afterBeanDiscovery, BeanManager beanManager) {
        if (definition != null) {
            afterBeanDiscovery.addBean()
                    .types(OpenIdAuthenticationDefinition.class)
                    .scope(ApplicationScoped.class)
                    .id("OpenId Definition")
                    .createWith(cc -> this.definition);
        }
    }

}
