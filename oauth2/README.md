# Security Connector - OAuth 2.0 Client

## Summary
The security connector project contains a OpenID Connect Client implementation and
provides a `@OAuth2AuthorisationMechanism` annotation that creates an authorization 
mechanism to authorize a user through the OAuth 2.0 standard protocol.

## Example
Here’s an example that configures a Google OAuth2 endpoint:
````
@OAuth2AuthenticationDefinition(
    authEndpoint="https://accounts.google.com/o/oauth2/v2/auth",
    tokenEndpoint="https://www.googleapis.com/oauth2/v4/token",
    clientId="{my-key}.apps.googleusercontent.com",
    clientSecret="{my-secret}",
    redirectURI="https://localhost:8181/{my-application}/callback",
    scope="email",
    extraParameters = {
        "testKey=testValue",
        "testKey2=testValue2"
    }
)
````

## Documentation
Full documentation is available here: https://docs.payara.fish/documentation/payara-server/public-api/oauth-support.html