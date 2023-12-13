/*
 * Copyright (c) 2023 Payara Foundation and/or its affiliates. All rights reserved.
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
package fish.payara.security.annotations;

import java.lang.annotation.Retention;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

/**
 * The {@link ProxyDefinition} annotation is used to specify proxy
 * mapping details within the OpenID Connect client configuration. It provides
 * configuration for handling requests passing through a reverse web proxy.
 *
 * @author jGauravGupta
 */
@Retention(RUNTIME)
public @interface ProxyDefinition {

    /**
     * Specifies the hostname of the proxied server.
     *
     * @return The hostname of the proxied server.
     */
    String hostName();

    /**
     * Specifies the port of the proxied server.
     *
     * @return The port of the proxied server.
     */
    String port();

    /**
     * The Microprofile Config key for the proxied server's hostname is
     * <code>{@value}</code>.
     */
    String OPENID_MP_PROXY_HOSTNAME = "payara.security.openid.proxyHostname";

    /**
     * The Microprofile Config key for the proxied server's port is
     * <code>{@value}</code>.
     */
    String OPENID_MP_PROXY_PORT = "payara.security.openid.proxyPort";
}
