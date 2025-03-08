package fish.payara.security.openid.cdi;

import fish.payara.security.connectors.annotations.OpenIdAuthenticationDefinition;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Vetoed;

@OpenIdAuthenticationDefinition(
        providerURI = "https://provider1.example.com",
        clientId = "client1",
        clientSecret = "secret1"
)
@Vetoed
@ApplicationScoped
class VetoedAuthConfig {
}
