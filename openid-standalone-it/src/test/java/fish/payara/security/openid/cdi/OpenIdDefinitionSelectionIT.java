package fish.payara.security.openid.cdi;

import fish.payara.security.connectors.annotations.OpenIdAuthenticationDefinition;
import fish.payara.security.openid.idp.OpenIdDeployment;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Alternative;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.OperateOnDeployment;
import org.jboss.arquillian.junit5.ArquillianExtension;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import jakarta.inject.Inject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@ExtendWith(ArquillianExtension.class)
public class OpenIdDefinitionSelectionIT {

    @Inject
    OpenIdAuthenticationDefinition authDefinition;

    @Deployment(name = "vetoed")
    public static WebArchive createVetoed() {
        return OpenIdDeployment.withStandaloneConnector(ShrinkWrap.create(WebArchive.class))
                .addClasses(VetoedAuthConfig.class, ActiveAuthConfig.class);
    }

    @Deployment(name = "alternative")
    public static WebArchive createAlternative() {
        return OpenIdDeployment.withStandaloneConnector(ShrinkWrap.create(WebArchive.class))
                .addClasses(AlternativeAuthConfig1.class, AlternativeAuthConfig2.class)
                .add(new StringAsset("<beans xmlns=\"https://jakarta.ee/xml/ns/jakartaee\"\n" +
                        "        xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n" +
                        "        xsi:schemaLocation=\"https://jakarta.ee/xml/ns/jakartaee https://jakarta.ee/xml/ns/jakartaee/beans_3_0.xsd\"\n" +
                        "        version=\"3.0\">\n" +
                        "   <alternatives>\n" +
                        "      <class>" + AlternativeAuthConfig2.class.getName() + "</class>\n" +
                        "   </alternatives>\n" +
                        "</beans>"), "META-INF/beans.xml");
    }

    @Test
    @OperateOnDeployment("vetoed")
    public void testVetoedConfig() {
        assertNotNull(authDefinition);
        assertEquals("https://provider2.example.com", authDefinition.providerURI());
        assertEquals("client2", authDefinition.clientId());
        assertEquals("secret2", authDefinition.clientSecret());
    }

    @Test
    @OperateOnDeployment("alternative")
    public void testAlternativeConfig() {
        assertNotNull(authDefinition);
        assertEquals("https://provider4.example.com", authDefinition.providerURI());
        assertEquals("client4", authDefinition.clientId());
        assertEquals("secret4", authDefinition.clientSecret());
    }

    @OpenIdAuthenticationDefinition(
            providerURI = "https://provider3.example.com",
            clientId = "client3",
            clientSecret = "secret3"
    )
    @Alternative
    @ApplicationScoped
    static class AlternativeAuthConfig1 {
    }

    @OpenIdAuthenticationDefinition(
            providerURI = "https://provider4.example.com",
            clientId = "client4",
            clientSecret = "secret4"
    )
    @Alternative
    @ApplicationScoped
    static class AlternativeAuthConfig2 {
    }
}