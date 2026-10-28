# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until 1.0, a minor version may break
backward compatibility; each such break is listed here.

## [Unreleased]

## [0.1.0] - 2026-10-28

First release. PHP 8.3+, Symfony 7.4.20+ or 8.1.8+, tested against Keycloak 26.

### Added

- The `keycloak` firewall authenticator: Symfony's access-token authenticator over its OIDC token
  handler, verifying bearers against one or several realms (keys bound per issuer), plus
  `other_issuers` for OpenID providers that are not Keycloak.
- Principal resolution through `ClaimsResolverInterface`, by issuer, then by the token's `azp`
  (`by_client`), then the firewall's default resolver.
- Token extractors for the `Authorization` header and an access cookie, and `SessionCookies` to set,
  clear and read a backend-for-frontend session.
- `KeycloakClient`: any token grant, client credentials, the direct grant (with extra fields for SPI
  authenticators), authorization code with PKCE, refresh, logout, the RP-initiated logout URL,
  revocation, userinfo, and `realm()` for SPI realm resources, with typed exceptions.
- `ServiceToken`: a client-credentials token per configured client, cached until it nearly expires.
- `dev_tokens`: literal bearers for local development, refused in `prod` and with debug off.
- `KeycloakStub`: a test realm with discovery, JWKS, signed tokens and hooks for custom grants and
  endpoints.

[Unreleased]: https://github.com/vinh0809it/keycloak-bundle/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vinh0809it/keycloak-bundle/releases/tag/v0.1.0
