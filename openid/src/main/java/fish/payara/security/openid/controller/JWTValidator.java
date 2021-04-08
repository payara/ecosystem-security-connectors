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

package fish.payara.security.openid.controller;

import java.text.ParseException;
import java.util.concurrent.ConcurrentHashMap;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import fish.payara.security.openid.api.OpenIdConstant;
import fish.payara.security.openid.domain.OpenIdConfiguration;

import static com.nimbusds.jose.jwk.source.RemoteJWKSet.DEFAULT_HTTP_SIZE_LIMIT;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.isNull;

@ApplicationScoped
public class JWTValidator {
    @Inject
    OpenIdConfiguration configuration;

    private ConcurrentHashMap<CacheKey, JWSKeySelector> jwsCache = new ConcurrentHashMap<>();
    private ConcurrentHashMap<CacheKey, JWEKeySelector> jweCache = new ConcurrentHashMap<>();


    public JWTClaimsSet validateBearerToken(JWT token, JWTClaimsSetVerifier jwtVerifier) {
        JWTClaimsSet claimsSet;
        try {
            if (token instanceof PlainJWT) {
                PlainJWT plainToken = (PlainJWT) token;
                claimsSet = plainToken.getJWTClaimsSet();
                jwtVerifier.verify(claimsSet, null);
            } else if (token instanceof SignedJWT) {
                SignedJWT signedToken = (SignedJWT) token;
                JWSHeader header = signedToken.getHeader();
                String alg = header.getAlgorithm().getName();
                if (isNull(alg)) {
                    // set the default value
                    alg = OpenIdConstant.DEFAULT_JWT_SIGNED_ALGORITHM;
                }

                ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
                jwtProcessor.setJWSKeySelector(getJWSKeySelector(alg));
                jwtProcessor.setJWTClaimsSetVerifier(jwtVerifier);
                claimsSet = jwtProcessor.process(signedToken, null);
            } else if (token instanceof EncryptedJWT) {
                /**
                 * If ID Token is encrypted, decrypt it using the keys and
                 * algorithms
                 */
                EncryptedJWT encryptedToken = (EncryptedJWT) token;
                JWEHeader header = encryptedToken.getHeader();
                String alg = header.getAlgorithm().getName();

                ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
                jwtProcessor.setJWSKeySelector(getJWSKeySelector(alg));
                jwtProcessor.setJWEKeySelector(getJWEKeySelector());
                jwtProcessor.setJWTClaimsSetVerifier(jwtVerifier);
                claimsSet = jwtProcessor.process(encryptedToken, null);
            } else {
                throw new IllegalStateException("Unexpected JWT type : " + token.getClass());
            }
        } catch (ParseException | BadJOSEException | JOSEException ex) {
            throw new IllegalStateException(ex);
        }
        return claimsSet;
    }

    /**
     * JWSKeySelector finds the JSON Web Key Set (JWKS) from jwks_uri endpoint
     * and filter for potential signing keys in the JWKS with a matching kid
     * property.
     *
     * @param alg the algorithm for the key
     * @return the JSON Web Signing (JWS) key selector
     */
    private JWSKeySelector<?> getJWSKeySelector(String alg) {
        return jwsCache.computeIfAbsent(createCacheKey(alg), k -> createJWSKeySelector(alg));
    }

    private CacheKey createCacheKey(String alg) {
        return new CacheKey(alg,
                configuration.getEncryptionMetadata().getEncryptionAlgorithm(),
                configuration.getEncryptionMetadata().getEncryptionMethod(),
                configuration.getEncryptionMetadata().getPrivateKeySource(),
                configuration.getJwksConnectTimeout(),
                configuration.getJwksReadTimeout(),
                configuration.getProviderMetadata().getJwksURL(),
                configuration.getClientSecret());
    }


    /**
     * JWEKeySelector selects the key to decrypt JSON Web Encryption (JWE) and
     * validate encrypted JWT.
     *
     * @return the JSON Web Encryption (JWE) key selector
     */
    private JWEKeySelector<?> getJWEKeySelector() {
        return jweCache.computeIfAbsent(createCacheKey(null), k -> createJweKeySelector());
    }

    private JWEKeySelector<?> createJweKeySelector() {
        JWEAlgorithm jwsAlg = configuration.getEncryptionMetadata().getEncryptionAlgorithm();
        EncryptionMethod jweEnc = configuration.getEncryptionMetadata().getEncryptionMethod();
        JWKSource<?> jwkSource = configuration.getEncryptionMetadata().getPrivateKeySource();

        if (isNull(jwsAlg)) {
            throw new IllegalStateException("Missing JWE encryption algorithm ");
        }
        if (!configuration.getProviderMetadata().getIdTokenEncryptionAlgorithmsSupported().contains(jwsAlg.getName())) {
            throw new IllegalStateException("Unsupported ID tokens algorithm :" + jwsAlg.getName());
        }
        if (isNull(jweEnc)) {
            throw new IllegalStateException("Missing JWE encryption method");
        }
        if (!configuration.getProviderMetadata().getIdTokenEncryptionMethodsSupported().contains(jweEnc.getName())) {
            throw new IllegalStateException("Unsupported ID tokens encryption method :" + jweEnc.getName());
        }

        return new JWEDecryptionKeySelector<>(jwsAlg, jweEnc, jwkSource);
    }

    private JWSKeySelector<?> createJWSKeySelector(String alg) {
        JWKSource<?> jwkSource;
        JWSAlgorithm jWSAlgorithm = new JWSAlgorithm(alg);
        if (Algorithm.NONE.equals(jWSAlgorithm)) {
            throw new IllegalStateException("Unsupported JWS algorithm : " + jWSAlgorithm);
        } else if (JWSAlgorithm.Family.RSA.contains(jWSAlgorithm)
                || JWSAlgorithm.Family.EC.contains(jWSAlgorithm)) {
            ResourceRetriever jwkSetRetriever = new DefaultResourceRetriever(
                    configuration.getJwksConnectTimeout(),
                    configuration.getJwksReadTimeout(),
                    DEFAULT_HTTP_SIZE_LIMIT
            );
            jwkSource = new RemoteJWKSet<>(configuration.getProviderMetadata().getJwksURL(), jwkSetRetriever);
        } else if (JWSAlgorithm.Family.HMAC_SHA.contains(jWSAlgorithm)) {
            byte[] clientSecret = new String(configuration.getClientSecret()).getBytes(UTF_8);
            if (isNull(clientSecret)) {
                throw new IllegalStateException("Missing client secret");
            }
            jwkSource = new ImmutableSecret<>(clientSecret);
        } else {
            throw new IllegalStateException("Unsupported JWS algorithm : " + jWSAlgorithm);
        }
        return new JWSVerificationKeySelector<>(jWSAlgorithm, jwkSource);
    }

}
