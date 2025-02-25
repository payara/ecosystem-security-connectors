package fish.payara.security.openid.cdi;

import fish.payara.security.connectors.annotations.OpenIdAuthenticationDefinition;
import jakarta.enterprise.context.ApplicationScoped;

@OpenIdAuthenticationDefinition(
        providerURI = "https://provider2.example.com",
        clientId = "client2",
        clientSecret = "secret2"
)
@ApplicationScoped
class ActiveAuthConfig {
}
