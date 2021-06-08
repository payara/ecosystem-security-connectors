# Changelog

# Version 2.0.0
4 June 2021
* **BREAKING:** Caller Name and Groups claims are now searched in reverse order - Access Token first, then IdentityToken and finally UserInfo claims
* **BREAKING:** `OpenIdClaims` is now read-only interface with all returned claims being `Optional`.
* Call OpenID userinfo endpoint lazily
* Do not fail with NPE when logout is invoked on session that's not logged in via OpenID connect
* Support Bearer Authentication for OpenID Connect
* Bump nimbus-jose-jwt to 9.2
* Add standalone distribution of OpenID Connect connector. Uses different API package names


# Version 1.1.0
24 Jul 2020

* Upgrade nimbus-jose-jwt to 8.2.1
* Validate AccessToken expiration on each request
* Sync API changes from upstream

# Version 1.0
25 Nov 2019

* Port from [payara/payara](https://github.com/payara/payara) to standalone repo
