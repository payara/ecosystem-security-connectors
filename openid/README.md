# Security Connector - OpenID Connect Client

## Summary
The security connector project contains a OpenID Connect Client implementation and
provides a `@OpenIdAuthenticationDefinition` annotation that creates an authorization 
mechanism to authenticate a user into secured application to an OpenID Connect Server
through the OpenID Connect standard protocol.

## Example
Here’s an example that configures a OpenID Connect client:
````
@OpenIdAuthenticationDefinition(
       providerURI = "https://sample-openid-server.com",
       clientId = "87068hgfg5675htfv6mrucov57bknst.apps.sample.com",
       clientSecret = "{my-secret}",
       redirectURI = "${baseURL}/callback",
       extraParameters = {
            "testKey=testValue",
            "testKey2=testValue2"
       }
)
public class SecurityBean {

}
````

## Documentation
Full documentation is available here: https://docs.payara.fish/documentation/payara-server/public-api/openid-connect-support.html