/*
 * Copyright (c) 2020-2021 Payara Foundation and/or its affiliates. All rights reserved.
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
import fish.payara.security.openid.controller.JWTValidator;
import fish.payara.security.openid.controller.NonceController;
import fish.payara.security.openid.controller.ProviderMetadataContoller;
import fish.payara.security.openid.controller.StateController;
import fish.payara.security.openid.controller.TokenController;
import fish.payara.security.openid.controller.UserInfoController;
import fish.payara.security.openid.domain.OpenIdContextImpl;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.context.Dependent;
import jakarta.enterprise.context.SessionScoped;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Any;
import jakarta.enterprise.inject.spi.*;
import jakarta.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import jakarta.security.enterprise.identitystore.IdentityStore;
import jakarta.security.enterprise.identitystore.IdentityStoreHandler;

import java.util.Set;
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
    private Class<?> definitionSource;
    private boolean definitionActive;
    private Producer<IdentityStoreHandler> storeHandlerWorkaroundProducer;

    protected void registerTypes(@Observes BeforeBeanDiscovery before) {
        registerTypes(before,
                AuthenticationController.class,
                ConfigurationController.class,
                NonceController.class,
                ProviderMetadataContoller.class,
                StateController.class,
                TokenController.class,
                UserInfoController.class,
                OpenIdContextImpl.class,
                OpenIdIdentityStore.class,
                AccessTokenIdentityStore.class,
                OpenIdAuthenticationMechanism.class,
                JWTValidator.class
        );
    }

    private void registerTypes(BeforeBeanDiscovery event, Class<?>... classes) {
        for (Class<?> aClass : classes) {
            event.addAnnotatedType(aClass, aClass.getName());
        }
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
        validateExtraParametersFormat(definition);
        this.definitionSource = sourceClass;
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

    protected void watchActiveBeans(@Observes ProcessBean<?> processBean) {
        if (definitionSource != null && definitionSource.equals(processBean.getAnnotated().getBaseType())) {
            definitionActive = true;
        }
    }

    protected void watchForInjectionWorkaround(@Observes @Any ProcessProducer<?,IdentityStoreHandler> workedAroundBean) {
        if (!workedAroundBean.getAnnotatedMember().isAnnotationPresent(InjectionWorkaround.class)) {
            return;
        }
        this.storeHandlerWorkaroundProducer = workedAroundBean.getProducer();
    }

    protected void redefineConfigControllerScope(@Observes ProcessBeanAttributes<ConfigurationController> controller) {
        Config mpConfig = ConfigProvider.getConfig();
        boolean sessionScopedConfig = false;
        try {
            sessionScopedConfig = mpConfig.getOptionalValue(OpenIdAuthenticationDefinition.OPENID_MP_SESSION_SCOPED_CONFIGURATION, boolean.class)
                    .orElse(false);
        } catch (IllegalArgumentException e) {
            LOGGER.warning("The value of " + OpenIdAuthenticationDefinition.OPENID_MP_SESSION_SCOPED_CONFIGURATION + "is not a boolean value. The OpenID connector will be configured only once for all requests.");
        }
        if (sessionScopedConfig) {
            LOGGER.info("Using per-session OpenIdConfiguration");
            controller.configureBeanAttributes().scope(SessionScoped.class);
        }
    }

    protected void registerDefinition(@Observes AfterBeanDiscovery afterBeanDiscovery, BeanManager beanManager) {

        if (definitionActive) {
            // if definition is active we broaden the type of OpenIdAuthenticationMechanism back to
            // HttpAuthenticationMechanism, so it would be picked up by Jakarta Security.
            afterBeanDiscovery.addBean()
                    .beanClass(HttpAuthenticationMechanism.class)
                    .addType(HttpAuthenticationMechanism.class)
                    .id(OpenIdExtension.class.getName()+"/OpenIdAuthenticationMechanism")
                    .scope(ApplicationScoped.class)
                    .produceWith(in -> in.select(OpenIdAuthenticationMechanism.class).get())
                    .disposeWith((inst,callback) -> callback.destroy(inst));

            afterBeanDiscovery.addBean()
                    .beanClass(IdentityStore.class)
                    .addType(IdentityStore.class)
                    .id(OpenIdExtension.class.getName()+"/OpenIdIdentityStore")
                    .scope(ApplicationScoped.class)
                    .produceWith(in -> in.select(OpenIdIdentityStore.class).get())
                    .disposeWith((inst,callback) -> callback.destroy(inst));

            afterBeanDiscovery.addBean()
                    .beanClass(IdentityStore.class)
                    .addType(IdentityStore.class)
                    .id(OpenIdExtension.class.getName()+"/AccessTokenIdentityStore")
                    .scope(ApplicationScoped.class)
                    .produceWith(in -> in.select(AccessTokenIdentityStore.class).get())
                    .disposeWith((inst,callback) -> callback.destroy(inst));

            afterBeanDiscovery.addBean()
                    .beanClass(OpenIdAuthenticationDefinition.class)
                    .types(OpenIdAuthenticationDefinition.class)
                    .scope(ApplicationScoped.class)
                    .id("OpenId Definition")
                    .createWith(cc -> this.definition);

            if (storeHandlerWorkaroundProducer != null) {
                // the fact that it is here means that we are likely to have an injection problem and need to add the
                // bean into our bean manager
                Set<Bean<?>> workaroundBeans = beanManager.getBeans(IdentityStoreHandler.class, InjectionWorkaround.LITERAL);
                if (workaroundBeans.isEmpty()) {
                    afterBeanDiscovery.addBean()
                            .beanClass(IdentityStoreHandler.class)
                            .types(IdentityStoreHandler.class)
                            .addQualifier(InjectionWorkaround.LITERAL)
                            .createWith(storeHandlerWorkaroundProducer::produce)
                            .destroyWith((inst, cc) -> storeHandlerWorkaroundProducer.dispose(inst));
                }
            }
        } else {
            // Publish empty definition to prevent injection errors. The helper components will not work, but
            // will not cause definition error. This is quite unlucky situation, but when definition is on an
            // alternative bean we don't know before this moment whether the bean is enabled or not.
            afterBeanDiscovery.addBean()
                    .beanClass(OpenIdAuthenticationDefinition.class)
                    .types(OpenIdAuthenticationDefinition.class)
                    .scope(Dependent.class)
                    .id("Null OpenId Definition")
                    .createWith(cc -> null);
        }
    }

}
