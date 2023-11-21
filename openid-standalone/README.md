# The standalone OpenID Connect connector

Here's the main documentation for features already integrated in Payara Platform runtimes:

* [Open ID Connect Support](https://docs.payara.fish/community/docs/documentation/payara-server/public-api/openid-connect-support.html) in Payara Platform Community documentation
* [Open ID Connect Support](https://docs.payara.fish/enterprise/docs/documentation/payara-server/public-api/openid-connect-support.html) in Payara Platform Enterprise documentation

If you use this standalone connector, import classes with the with the `fish.payara.security.connectors` package instead of the `fish.payara.security`.

## Download the standalone OpenID Connect connector

You can access the latest version in the [Payara Artifacts Maven Repository](https://nexus.dev.payara.fish/service/rest/repository/browse/payara-artifacts/fish/payara/security/connectors/openid-standalone/). 

You can also add the Payara Artifacts repository into your pom.xml and define the dependency as follows (replace VERSION with the latest version):

```
    <repositories>
        <repository>
            <id>payara-nexus-artifacts</id>
            <url>https://nexus.dev.payara.fish/repository/payara-artifacts</url>
            <releases>
                <enabled>true</enabled>
            </releases>
            <snapshots>
                <enabled>false</enabled>
            </snapshots>
        </repository>
    </repositories>

    <dependencies>
        <dependency>
            <groupId>fish.payara.security.connectors</groupId>
            <artifactId>openid-standalone</artifactId>
            <version>VERSION</version>
        </dependency>        
    </dependencies>
```


### Support for multitenancy

By default, the same configuration of the OpenID connector is applied for the whole application, for all authentication attempts. In a multitenant scenario, each tenant should be able to supply a different configuration. This is implemented by an optional session scope for the configuration, which means that the configuration is evaluated for each user session. Therefore it's possible to dynamically adjust the configuration before each authantication attempt, e.g. based on the URL, domain in the URL or any other information in the incoming HTTP request. 

However, it's not possible to use a different configuration for different secured resources. Once a user is authenticated, the authentication information is saved in the HTTP session until the user logs out. All secure resources will be accessed using the same user.

Multitenancy is disabled by default for performance reasons. To enable it, set the MicroProfile Configuration property `payara.security.openid.sessionScopedConfiguration` to `true`. To specify it directly in the application, you can place it in the [microprofile-config.properties](https://download.eclipse.org/microprofile/microprofile-config-1.4/microprofile-config-spec.html#default_configsources) file.

_NOTE: If you use the security connector in EAR and you want to specify configuration properties in `microprofile-config.properties`, note that you need to place the `microprofile-config.properties` file in a JAR file in the `lib` directory in the `EAR`. This will make the properties visible for all modules in the EAR. If you place the `microprofile-config.properties` file only in the WAR inside the EAR, it will be ignored even if you use the connector only in the WAR application._

Dynamic configuration is possible using Expression Language to specify the properties in the configuration annotations as described in [Payara Community](https://docs.payara.fish/community/docs/documentation/payara-server/public-api/openid-connect-support.html#el-support) and [Payara Enterprise](https://docs.payara.fish/enterprise/docs/documentation/payara-server/public-api/openid-connect-support.html#el-support) documentation.

#### Example for multitenancy

Create microprofile-config.properties in your application, in the META-INF directory, with the following contents:

```
payara.security.openid.employee.providerURI=<EMPLOYEE_OPENID_PROVIDER_URI>
payara.security.openid.dealer.providerURI=<DEALER_OPENID_PROVIDER_URI>
payara.security.openid.sessionScopedConfiguration=true
```

Apply the following configuration using the `OpenIdAuthenticationDefinition` annotation:

```
@OpenIdAuthenticationDefinition(
        providerURI = "#{openidConfigBean.tokenEndpointURL}",
        clientId = CLIENT_ID_VALUE,
        clientSecret = CLIENT_SECRET_VALUE,
        redirectURI = "${baseURL}/Callback"
)
```

Create `OpenidConfigBean` class with the `tokenEndpointURL` method. This class can be a CDI bean that injects `HttpServletRequest` to get information about which tenant to use. it will also inject `Config` to retrieve the configuration about each tenant from the `microprofile-config.properties` file:

```
@Named
public class OpenidConfigBeanEL {
    
    @Inject
    HttpServletRequest request;
    
    @Inject
    Config config;
    
    private static final String BASE_OPENID_KEY = "payara.security.openid";
    
    public String getTokenEndpointURL() {
        String tenant = getTenant(request);  // a custom method to decide which tenant to use
        return config
                .getOptionalValue(BASE_OPENID_KEY + "." + tenant + ".providerURI", String.class)
                // e.g. payara.security.openid.employee.providerURI
                .orElseGet(() -> {
                    // read config for the employee tenant by default
                   return config.getValue(BASE_OPENID_KEY + ".employee.providerURI", String.class);
                });
    }
    
}
