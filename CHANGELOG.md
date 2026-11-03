# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until 1.0, a minor version may break
backward compatibility; each such break is listed here.

## [Unreleased]

### Security

- `BrowserLogin` accepted return URLs a browser reads differently than `parse_url()` does, leading
  elsewhere after the login: `https://evil.test\.apps.example.com` against a `https://*.apps.example.com`
  return origin (a browser reads the backslash as a slash), and paths holding a tab or a newline
  (`/\t/evil.test`). A return URL holding a control character, a space or a backslash, or whose
  host is not plain letters, digits, dots and hyphens, is refused now.
- A realm's ID and logout tokens were accepted as access tokens when their `aud` held the
  firewall's audience (an ID token's is the client it was issued to). A realm's token whose `typ`
  is not `Bearer` is refused now; the other issuers' tokens are not checked.

- A realm that could not be reached failed every token with a 401, which clients take for a
  sign-out, and one token with a bad signature during an outage dropped the cached keys for good:
  every request then refetched them and failed until the realm was back. A provider that cannot be
  reached is a `KeycloakUnavailableException` now (a server error), and a refetch that cannot reach
  it puts the keys it dropped back for five minutes.

### Changed

- `dev_tokens` are allowed only in the `dev` and `test` environments (with debug on), no longer in
  any environment but `prod`.
- `cookies.refresh.path` is required: the refresh token should reach only the routes that refresh
  and end the session, not every route as the former default `/` sent it.
- A service token's cache key includes its realm and client id, so a client retargeted under the
  same name, or another app on the same pool, mints its own. Tokens cached before the upgrade are
  minted again once.
- The client's grant fields, PKCE verifier and code are `#[\SensitiveParameter]`, out of stack
  traces.
- The bundle's plumbing classes are marked `@internal`.

### Added

- `ServiceToken::forget()`, for a token a downstream service refused before it expired.
- `KeycloakStub::failWith()` and `recover()`: a realm that is down.

## [0.3.0] - 2026-11-02

### Added

- Autowiring by argument name for each client's services: `KeycloakClient $<name>Client`,
  `BrowserLogin $<name>Login` and `ServiceToken $<name>Token` (`mobile-app` becomes
  `$mobileAppClient`). The only client also autowires by its bare type, as does the only
  confidential client's `ServiceToken`; `SessionCookies` always does. The service ids are unchanged.
- `by_realm` entries may resolve per client: `employees: { by_client: { web: ... }, resolver: ... }`.
  A realm's tokens are resolved among its own entry alone, so two realms can each have a client of
  the same id, and a client the entry does not list is refused unless it has a `resolver`. The
  short form, `employees: App\Security\StaffResolver`, is unchanged.

### Changed

- `ClaimsUserProvider`'s `$byIssuer` entries carry a `byClient` map and may have a null
  `resolver`. It is built by the bundle; only code constructing it directly is affected.

### Fixed

- The error for a missing SecurityBundle no longer claims it must come before this bundle in
  `config/bundles.php`; the order does not matter.

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

[Unreleased]: https://github.com/vinh0809it/keycloak-bundle/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/vinh0809it/keycloak-bundle/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/vinh0809it/keycloak-bundle/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/vinh0809it/keycloak-bundle/releases/tag/v0.1.0
