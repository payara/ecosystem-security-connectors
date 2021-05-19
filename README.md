# Security Connectors Suite

Connectors suite for security plugins and extensions for the Payara Platform

**ATTENTION**: Support for this repository is handled in the [Ecosystem Support repository](https://github.com/payara/ecosystem-support)

The connectors bundled in Payara Platform Community edition are documented in the [Payara Platform Community documentation](https://docs.payara.fish/community/docs/documentation/payara-server/public-api/README.html).

The connectors bundled in Payara Platform Enterprise edition are documented in the [Payara Platform Enterprise documentation](https://docs.payara.fish/enterprise/docs/documentation/payara-server/public-api/README.html).

It's also possible to add these connectors to your application and run the application on any Java EE 8 or Jakarta EE runtime which supports the Security API. 

In case you'd like to use a newer version of a connector on one of the Payara Platform runtimes (e.g. on Payara Server) which already contain an older version of the container, you need to do one of the 2 following things to select the version in your application:

* add a standard container into your application and disable classloading delegation (see ho to do it in [Payara Community](https://docs.payara.fish/community/docs/documentation/payara-server/classloading.html#disable-classloading-delegation) and [Payara Enterprise](https://docs.payara.fish/enterprise/docs/documentation/payara-server/classloading.html#disable-classloading-delegation))
* or add a standalone variant of the container in your application and import classes with the `fish.payara.security.connectors` package instead of the `fish.payara.security`

## Standalone variants of connectors

Standalone connectors provide the same functionality as the standard connectors. But while the standard connectors are built to be integrated with Payara Platform runtimes (e.g. Payara Server), the standalone connectors are built to be safely included in the applications deployed to a Payara Platform runtime without any conflicts with the connectors in the runtime. This is done by shading the classes in teh connector and all its dependencies so that are in a different package name.

A standalone connector can be added into your application as a JAR library (or as a compile-time dependency in a WAR Maven project). In order to use it, follow the documentation of the standard connectors but use the `fish.payara.security.connectors` package instead of the `fish.payara.security` to import the classes.

The following security connectors have standalone variants. Click on them to see documentation of the latest features that aren't yet integrated in the Payara Platform:

* [OpenID Connect standalone connector](openid-standalone/README.md)

