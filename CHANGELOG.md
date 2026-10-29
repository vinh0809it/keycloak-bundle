# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until 1.0, a minor version may break
backward compatibility; each such break is listed here.

## [Unreleased]

## [0.2.0] - 2026-10-29

### Added

- `keycloak.browser_login.<name>` for every client: the browser's authorization code flow with
  PKCE, `start()` keeping the state and verifier in a signed login cookie, `finish()` checking the
  state and `iss` and exchanging the code, and spending the code of any callback it refuses so it
  cannot be redeemed elsewhere. The page to return to is a path of the app or a URL on
  one of the client's `return_origins`. `LoginFailedException`, with the OAuth `error` and the page
  the login meant to return to, when it cannot complete.
- `KeycloakClient::issuer()`.
- Key rotation: a token no cached key verifies has the firewall's keys fetched afresh and is
  verified once more, at most once a minute per firewall. `KeycloakStub::rotateKey()` to test it.
- `Claims::roles()`: the realm roles, and one client's, as Symfony roles.
- `by_realm` on the `keycloak` authenticator: a resolver for every token of one realm, matched by
  issuer like `other_issuers`, before `by_client`.
- `success_handler` and `failure_handler` on the `keycloak` authenticator.
- `dev_tokens` patterns with `{claim}` placeholders (`{azp}~{sub}`). A pattern must hold a character
  no JWT does, so it never takes a real token.
- `KeycloakStubRouter`, several stubs behind one `mock_response_factory`; `onGrant()` handlers get
  the stub that was asked, and `KeycloakStub::$requests` records each request's `_issuer`.
- `TokenSet::$scope` and `TokenSet::$tokenType`.
- A warning, once per process, when a firewall with several issuers runs on a
  `symfony/security-http` that does not bind keys to their issuer (before 7.4.20 / 8.1.8).

### Fixed

- Realm names with a `-` (`my-realm`) under `realms` and `by_realm` were renamed `my_realm`, so
  firewalls and clients naming them failed.
- A `dev_tokens` entry with no claims (`~`) was ignored; claims that are not a map, a repeated or
  invalid placeholder now fail the configuration instead of every request.
- `refresh.session_lifetime` accepts an env var; `same_site` is checked at configuration time;
  `cookie: true` without `keycloak.cookies` says so.
- A firewall left with no configured provider refuses tokens with a 401 instead of a 500.
- `KeycloakStub` announces and signs its issuer without a trailing slash, as the bundle expects it.

### Changed

- PHP 8.2+, `symfony/security-http` 7.4.13+ or 8.0.13+ (was 8.3+, 7.4.20+ or 8.1.8+). Several issuers
  on one firewall are fully isolated from 7.4.20 / 8.1.8 on.
- `KeycloakClient::authorizationUrl()` takes `scope` from `$extra` (a null one removes it); the
  client, redirect URI, state, PKCE and response mode stay the method's own.
- An explicit `issuer` is matched exactly as written, a trailing slash included; one derived from the
  URL still has none.
- Each `KeycloakStub` realm signs with its own key id, so several stubs verify on a
  `symfony/security-http` that pools their keys. Stub keys are regenerated once.

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

[Unreleased]: https://github.com/vinh0809it/keycloak-bundle/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/vinh0809it/keycloak-bundle/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/vinh0809it/keycloak-bundle/releases/tag/v0.1.0
