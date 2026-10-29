# Keycloak bundle for Symfony

[![QA](https://github.com/vinh0809it/keycloak-bundle/actions/workflows/qa.yml/badge.svg)](https://github.com/vinh0809it/keycloak-bundle/actions/workflows/qa.yml)
[![Packagist](https://img.shields.io/packagist/v/vinh0809it/keycloak-bundle)](https://packagist.org/packages/vinh0809it/keycloak-bundle)
[![PHP](https://img.shields.io/packagist/dependency-v/vinh0809it/keycloak-bundle/php)](composer.json)
[![License](https://img.shields.io/github/license/vinh0809it/keycloak-bundle)](LICENSE)

Keycloak realms, declared once, for a Symfony backend: trusting their tokens on a firewall and, for
the backends that need it, calling them.

The verification itself is Symfony's own `oidc` access-token handler (signature against the realm's
JWKS, `iss`, `aud`, `exp`), so this bundle adds no cryptography of its own. It splits the
configuration where it belongs: the realms, and what talks to them, once under `keycloak`, and each
firewall's own part as its `keycloak` authenticator in `security.yaml`.

## Requirements

| | Supported | Tested in CI |
|---|---|---|
| PHP | 8.2+ | 8.2, 8.3, 8.4, 8.5 |
| Symfony | 7.4.13+, 8.0.13+ | 7.4 (lowest and latest dependencies), 8.0, 8.1 |
| Keycloak | 26 | 26.5, 26.7, against a real server |

The floor is `symfony/security-http` 7.4.13 / 8.0.13, below which Symfony's `oidc` handler accepts
tokens missing `aud`, `iss` or `exp` (CVE-2026-45069). Symfony 8.0 is end of life and every 8.0
release of `symfony/http-foundation` is affected by CVE-2026-108082, so Composer refuses it unless
security blocking is turned off; prefer 8.1.

**Several issuers on one firewall** (several realms, or `other_issuers`) need
`symfony/security-http` 7.4.20 / 8.1.8 to be fully isolated from each other. Earlier releases verify a
token against the keys of every provider on the firewall, whatever its `iss`, so whoever holds the
private key of one provider can sign tokens claiming another. The bundle still runs on them and logs
a warning, once per process, when such a firewall is built.

## Install

```bash
composer require vinh0809it/keycloak-bundle
```

Symfony Flex registers the bundle. Without Flex, add it yourself:

```php
// config/bundles.php
Vinh0809it\KeycloakBundle\KeycloakBundle::class => ['all' => true],
```

## Quick start

Point the bundle at the realm and name the audience your API's tokens carry (an audience mapper on
the Keycloak client adds it):

```yaml
# config/packages/keycloak.yaml
keycloak:
    realm: '%env(KEYCLOAK_URL)%'          # e.g. https://sso.example.com/realms/my-realm
    audience: my-api
```

Put the `keycloak` authenticator on a stateless firewall:

```yaml
# config/packages/security.yaml
security:
    firewalls:
        api:
            pattern: ^/api
            stateless: true
            keycloak:
                resolver: App\Security\UserResolver
    access_control:
        - { path: ^/api, roles: IS_AUTHENTICATED_FULLY }
```

Turn the verified claims into your user:

```php
use Symfony\Component\Security\Core\User\UserInterface;
use Vinh0809it\KeycloakBundle\Security\Claims;
use Vinh0809it\KeycloakBundle\Security\ClaimsResolverInterface;

final readonly class UserResolver implements ClaimsResolverInterface
{
    public function __construct(private UserRepository $users) {}

    public function resolve(Claims $claims): UserInterface
    {
        return $this->users->findOneBy(['keycloakId' => $claims->sub])
            ?? $this->users->register($claims->sub, $claims->string('email'));
    }
}
```

A request with `Authorization: Bearer <access token>` now reaches your controllers as that user,
and anything else gets a 401.

## What it provides

- **Key rotation**: a token whose signature none of the cached keys verifies has the firewall's
  keys fetched afresh and is verified once more, at most once a minute per firewall, so a key the
  realm publishes is picked up without clearing a cache.
- **The `keycloak` authenticator** of a firewall: Symfony's access-token authenticator, verifying the
  bearer against the realms that firewall accepts, then turning the verified claims into the app's
  principal through a `ClaimsResolverInterface` chosen by the token's issuer (`by_realm`,
  `other_issuers`), else its `azp` (the Keycloak client it was minted for, `by_client`), else the
  firewall's default. A realm URL works with or without a trailing slash, and its issuer defaults to
  it. It brings its own user provider, and takes the firewall's own `success_handler` and
  `failure_handler`.
- **`keycloak.token_extractor.header`** and, when `cookies` is set,
  **`keycloak.token_extractor.cookie`**: where a firewall finds the token, the
  `Authorization: Bearer` header (Symfony's own extractor) and the access cookie. The firewall
  lists them in the order it tries them.
- **`keycloak.session_cookies`**, when `cookies` is set: a backend-for-frontend's session.
  `set(Response, TokenSet)` writes the access and refresh cookies (HttpOnly, Secure, expiring with
  their tokens), `clear(Response)` ends them, `refreshToken(Request)` reads the refresh token. The
  login and callback routes stay the app's, built on `keycloak.browser_login.<name>`.
- **`dev_tokens`**: bearers for local development answering with configured claims, through the
  same resolvers as a real token: literal (`user.1`) or with `{claim}` placeholders (`{azp}~{sub}`
  takes `mobile-app~42` as `azp: mobile-app, sub: 42`). A pattern needs a character no JWT holds
  outside its placeholders, such as `~` or `:`. Refused in `prod`.
- **`keycloak.client.<name>`** and **`keycloak.browser_login.<name>`** for each entry under
  `clients`, and **`keycloak.service_token.<name>`** for one with a secret. Nothing is registered
  when `clients` is empty. See *Calling the realm* and *Browser login*.
- **`Vinh0809it\KeycloakBundle\Test\KeycloakStub`**: the realm for a test suite. Discovery, a JWKS the real
  verifier checks against, signed tokens, the client-credentials grant, and hooks for the app's own
  grants (`onGrant()`, or `grant()` in a subclass) and SPI endpoints (`on()`).
  **`KeycloakStubRouter`** puts several of them behind one `mock_response_factory`.

## Configuration reference

```yaml
# config/packages/keycloak.yaml: the realm, and what talks to it
keycloak:
    realm: '%env(KEYCLOAK_BASE_URI)%'        # how this service reaches the realm
    issuer: '%env(KEYCLOAK_ISSUER)%'         # only when tokens name a different (public) URL
    audience: my-api
    cookies:                                 # optional: a backend-for-frontend's session
        access: { name: app_at, domain: '%env(WEB_COOKIE_DOMAIN)%' }   # path /, same_site lax
        refresh: { name: app_rt, path: /web, same_site: strict }        # optional
        # refresh.session_lifetime: 1209600  seconds for a refresh token without expiry; null = browser session
    clients:                                 # optional: only for a service that calls the realm
        service: { id: my-service, secret: '%env(SERVICE_CLIENT_SECRET)%', token_cache: cache.app }
        web: { id: web-app, secret: '%env(WEB_CLIENT_SECRET)%' }
        # web: { ..., return_origins: [https://web.example.com], login_cookie: { name: web_login, path: /auth } }
    # algorithms: [RS256]                    # RS*, PS* or ES*; anything else is refused

when@dev:
    keycloak:
        dev_tokens:                          # on every keycloak firewall; refused in prod and with debug off
            'user.1': { azp: mobile-app, username: 'user@example.com' }
            '{azp}~{sub}': { email_verified: true }   # any client, any subject
```

```yaml
# config/packages/security.yaml: each firewall's own part
security:
    firewalls:
        main:
            stateless: true
            keycloak:
                resolver: App\Security\MemberResolver
                by_client:                   # optional: azp => resolver, in whichever realm the client is
                    admin-web: App\Security\AdminResolver
                # by_realm: { employees: App\Security\StaffResolver }   # every token of that realm, before by_client
                cookie: true                 # optional: also read the access cookie, after the header
                # token_extractors: [keycloak.token_extractor.header, App\Security\OriginCookieExtractor]
                #                            # instead of cookie: extractor ids, tried in order
                # realms: [customers]         # with several realms
                # audience: ...              # to override keycloak.audience
                # other_issuers: [{ url, issuer, resolver }]   # OpenID providers other than the realms
                # success_handler: App\Security\OnSuccess   # AuthenticationSuccessHandlerInterface
                # failure_handler: App\Security\OnFailure   # AuthenticationFailureHandlerInterface; default a 401
```

The firewall must be `stateless`: the principal is rebuilt from each request's token and is never
reloaded from a session, so a stateful firewall is a configuration error. No `providers` entry is
needed for it, and the firewall order and the access rules stay the app's.
A decorator of the firewall's token handler (a legacy issuer, say) decorates
`keycloak.token_handler.<firewall>`. `entry_point` and `user_checker` are the firewall's own and work
as with any authenticator.

### Several realms

`realm:` + `issuer:` is the shorthand for one Keycloak realm, named `default`. A realm whose URL is
empty (its env var unset, as in a dev setup living on dev tokens) is not configured: it takes no
token, and nothing is fetched from it. With more, name them,
and say which ones each firewall accepts and which realm each client belongs to.

```yaml
keycloak:
    audience: shop-api
    realms:
        customers: { url: '%env(KEYCLOAK_CUSTOMERS_BASE_URI)%', issuer: '%env(KEYCLOAK_CUSTOMERS_ISSUER)%' }
        employees: { url: '%env(KEYCLOAK_EMPLOYEES_BASE_URI)%', issuer: '%env(KEYCLOAK_EMPLOYEES_ISSUER)%' }
    clients:
        web: { realm: customers, id: shop-web, secret: '%env(WEB_CLIENT_SECRET)%' }

security:
    firewalls:
        staff: { pattern: ^/staff, stateless: true, keycloak: { realms: [employees], resolver: App\Security\StaffResolver } }
        main: { stateless: true, keycloak: { realms: [customers], resolver: App\Security\CustomerResolver } }
```

### Other issuers and the app's own tokens

`realms` are Keycloak's. A firewall still has one bearer authenticator, as Symfony gives each
firewall one access-token authenticator: every other kind of bearer it takes goes through the
`keycloak` one too, rather than through a second authenticator beside it (which would see, and
refuse, Keycloak's tokens).

- **Another OpenID provider** (another service's own tokens, with discovery): list it under the
  firewall's `other_issuers`, with the resolver of its principals, and its `issuer` exactly as its
  tokens carry it (a trailing slash included). It is verified by the same
  handler (each provider's keys bound to its own issuer from `symfony/security-http` 7.4.20 / 8.1.8
  on, see *Requirements*), and resolved by issuer before `by_client`.
  An empty `url` (its env var unset) takes no token. Its tokens must carry the firewall's audience:
  one handler checks one.
- **A token the app issues itself**: decorate `keycloak.token_handler.<firewall>`, answer the
  bearers whose `iss` is the app's (`Vinh0809it\KeycloakBundle\Security\UnverifiedIssuer::of()`) and hand
  every other one on.

```yaml
security:
    firewalls:
        main:
            stateless: true
            keycloak:
                by_client: { mobile-app: App\Security\MobileResolver }
                other_issuers:
                    - { url: '%env(LEGACY_BASE_URI)%', issuer: '%env(LEGACY_ISSUER)%', resolver: App\Security\LegacyResolver }
```

```php
#[AsDecorator('keycloak.token_handler.main')]
final readonly class OwnTokenHandler implements AccessTokenHandlerInterface
{
    public function __construct(#[AutowireDecorated] private AccessTokenHandlerInterface $keycloak) {}

    public function getUserBadgeFrom(string $accessToken): UserBadge
    {
        return 'https://my-app' === UnverifiedIssuer::of($accessToken)
            ? $this->verifyMyOwn($accessToken)
            : $this->keycloak->getUserBadgeFrom($accessToken);
    }
}
```

A firewall or client that names no realm gets the only one declared; with several, leaving it out
is a configuration error rather than a guess.

`Claims::roles()` turns the realm roles, and one client's when given, into Symfony roles
(`offline_access` is `ROLE_OFFLINE_ACCESS`): `new User($claims->sub, $claims->roles('my-api'))`.

Apps name the bundle's services as strings, in YAML and in `#[Autowire]` alike; a typo fails the
container build. Inside the bundle the ids come from the constants on `KeycloakBundle`.

```php
final readonly class MemberResolver implements ClaimsResolverInterface
{
    public function resolve(Claims $claims): User
    {
        return $this->users->findOneBy(['keycloakSub' => $claims->sub])
            ?? $this->adopt($claims->sub, $claims->string('username'));
    }
}
```

## Calling the realm

A confidential client's `service_token` keeps its token for its lifetime minus 30 seconds. Under
php-fpm the container is rebuilt per request, so without `token_cache` every request mints its own;
with a pool, every request and worker share one.

`Vinh0809it\KeycloakBundle\Client\KeycloakClient` is one Keycloak client of the realm. It needs nothing of
Symfony beyond an `HttpClientInterface`, so it works outside the bundle too.

```php
public function __construct(
    #[Autowire(service: 'keycloak.service_token.service')] private ServiceToken $serviceToken,
    #[Autowire(service: 'keycloak.client.web')] private KeycloakClient $web,
) {}

$this->serviceToken->get();                                      // cached client-credentials token
$this->web->authorizationUrl($callback, $state, $challenge, ['login_hint' => $email]);
$this->web->exchangeCode($code, $callback, $verifier);           // TokenSet
$this->web->refresh($refreshToken);
$this->web->logout($refreshToken);
$this->web->revoke($refreshToken);
$this->web->userinfo($accessToken);                              // the user's claims; needs the openid scope
$this->web->logoutUrl($afterLogout, $idToken);                   // where a browser ends its SSO session

// An SPI: a direct grant with its own fields, and the realm's own resources.
$app->password($email, '', ['session' => $session, 'otp' => $otp]);
$app->realm('POST', 'my-provider/send', ['json' => ['to' => $email]]);
```

Failures say whose they are:

| Exception | Meaning | Usually |
|---|---|---|
| `RequestRefusedException` | Keycloak refused the request (a spent code, an expired refresh token, a wrong OTP) | 401 to the caller |
| `InvalidClientException` (a `RequestRefusedException`) | Keycloak refused THIS service's client (a wrong secret, a grant it may not use) | 502, never retry |
| `KeycloakUnavailableException` | unreachable, 5xx, or a success without a token | 502 |
| `LoginFailedException` | a browser's login could not be completed (see *Browser login*) | start a new login |

All of them implement `KeycloakException`.

## Browser login

`keycloak.browser_login.<name>` signs a browser in at the realm for each client under `clients`:
the authorization code flow with PKCE, with the `state`, the PKCE verifier, the redirect URI and the
page to return to kept in a short-lived login cookie (HttpOnly, Secure, SameSite=Lax, signed with
`kernel.secret`, 10 minutes). On the callback it checks the cookie, the `state` the realm sent back
and its `iss` (RFC 9207), then exchanges the code with the kept verifier. A callback it refuses has
its code spent (Keycloak invalidates a code on a failed exchange), so whoever started the login the
code belongs to cannot redeem it.

The page to return to is a path of this app, or a URL on one of the client's `return_origins`
(`https://web.example.com`, or `https://*.example.com` for its subdomains). `start()` refuses any
other, so the one the callback hands back is safe to redirect to.

```yaml
keycloak:
    cookies:
        access: { name: app_at, domain: '%env(COOKIE_DOMAIN)%' }
        refresh: { name: app_rt, path: /auth }
    clients:
        web: { id: web-app, secret: '%env(WEB_CLIENT_SECRET)%', return_origins: ['%env(WEB_ORIGIN)%'] }
```

A backend-for-frontend then needs four routes. The web navigates the browser to `/auth/login`
(a page load, not `fetch`), and calls the API with its cookies (`credentials: 'include'`):

```php
public function __construct(
    #[Autowire(service: 'keycloak.browser_login.web')] private BrowserLogin $login,
    #[Autowire(service: 'keycloak.client.web')] private KeycloakClient $web,
    #[Autowire(service: 'keycloak.session_cookies')] private SessionCookies $session,
) {}

#[Route('/auth/login', methods: ['GET'])]
public function login(Request $request): Response
{
    return $this->login->start(
        $this->generateUrl('auth_callback', [], UrlGeneratorInterface::ABSOLUTE_URL),
        $request->query->get('return'),
    );
}

// The realm redirects the browser here; the browser leaves for the page it came from.
#[Route('/auth/callback', name: 'auth_callback', methods: ['GET'])]
public function callback(Request $request): Response
{
    try {
        $done = $this->login->finish($request);
        $response = new RedirectResponse($done->returnTo ?? '/');
        $this->session->set($response, $done->tokens);       // the session: access + refresh cookies
    } catch (LoginFailedException $e) {
        // Back where the login meant to go, with why it did not happen (access_denied...).
        $response = new RedirectResponse(($e->returnTo ?? '/').'#login_error='.($e->error ?? 'failed'));
    }
    $this->login->clearLoginCookie($response);                // the login cookie is spent either way

    return $response;
}

#[Route('/auth/refresh', methods: ['POST'])]
public function refresh(Request $request): Response
{
    $response = new Response(null, 204);
    try {
        $this->session->set($response, $this->web->refresh((string) $this->session->refreshToken($request)));
    } catch (RequestRefusedException) {
        $response = new Response(null, 401);                  // the session is over: sign in again
        $this->session->clear($response);
    }

    return $response;
}

#[Route('/auth/logout', methods: ['POST'])]
public function logout(Request $request): Response
{
    $refreshToken = $this->session->refreshToken($request);
    if (null !== $refreshToken) {
        try {
            $this->web->logout($refreshToken);                // ends the Keycloak session too
        } catch (KeycloakException) {
        }
    }
    $response = new Response(null, 204);
    $this->session->clear($response);

    return $response;
}
```

`start()` takes further authorization parameters as its third argument (`scope`, `login_hint`,
`kc_idp_hint`, `prompt`...). The cookie-authenticated `POST` routes (refresh, logout, and the app's
own) need protection against cross-site requests: SameSite cookies cover other sites, not other
subdomains of the same site, so check the `Origin` header against the web's origin as well.

A browser holds one login at a time: one started in a second tab replaces the first, whose callback
then fails. The login cookie's name (`keycloak_login_<name>` by default), path and domain are set
under `clients.<name>.login_cookie`; its path must cover the callback. The ID token is not
verified, so there is no `nonce`: the session is the access and refresh tokens, which the firewall
verifies on each request.

## Extending with a Keycloak SPI

The bundle covers standard Keycloak and OpenID Connect only. A realm's own SPIs (an authenticator
reading extra fields on the direct grant, a realm resource under `/realms/{realm}/{provider}/...`)
are written beside it, from four primitives:

| For | Use |
|---|---|
| a grant an authenticator extends with its own fields | `KeycloakClient::token($grant)` or `password($user, $pass, $extra)` |
| an SPI's realm resource | `KeycloakClient::realm($method, $path, $options)`, with `auth_bearer` from a `ServiceToken` when it needs one |
| claims an SPI's mapper adds to the token | `Claims::get()`, `string()`, `list()` in a resolver |
| testing either | `KeycloakStub::on($method, $suffix, $handler)` and `onGrant($handler)` |

```php
final readonly class OtpLogin                       // in the app, or a package of its own
{
    public function __construct(private KeycloakClient $client) {}

    public function send(string $username): string
    {
        return $this->client->realm('POST', 'otp/send', ['json' => ['username' => $username]])['session'];
    }

    public function login(string $username, string $session, string $code): TokenSet
    {
        return $this->client->password($username, '', ['session' => $session, 'otp' => $code]);
    }
}
```

```yaml
services:
    App\Keycloak\OtpLogin: { arguments: ['@keycloak.client.app'] }
```

`tests/Unit/Client/SpiExample` holds this example with its test against the stub.

## Test

Register the stub as the `mock_response_factory` of the test environment's HTTP clients, and extend
it for the app's own grants:

```php
final class KeycloakStub extends \Vinh0809it\KeycloakBundle\Test\KeycloakStub
{
    public function __construct(
        #[Autowire(param: 'kernel.cache_dir')] string $cacheDir,
        #[Autowire(service: 'cache.app')] CacheItemPoolInterface $cache,
    ) {
        // The last argument names the firewalls that verify its tokens, whose cached keys it renews.
        parent::__construct('https://keycloak.test/realms/customers', $cacheDir, $cache, ['api']);
        $this->serviceClient('my-service', ['sub' => '...', 'azp' => 'my-service', 'aud' => ['other-api']]);
    }

    public function bearerFor(User $user): string
    {
        return $this->sign(['sub' => '...', 'azp' => 'mobile-app', 'aud' => 'my-api', 'username' => '...']);
    }
}
```

With several realms, or another OpenID provider, give each its own stub and route between them:

```php
$services->set(KeycloakStubRouter::class)->args([service(CustomersRealm::class), service(EmployeesRealm::class)]);
// framework.http_client.mock_response_factory: Vinh0809it\KeycloakBundle\Test\KeycloakStubRouter
```

Each request goes to the stub whose issuer URL it is under. A grant handler gets the stub that was
asked as its second argument, and `KeycloakStub::$requests` records each request's `_issuer`.

## Known limitations

- **Clock skew.** Symfony's `oidc` handler checks `iat`, `nbf` and `exp` with no leeway and offers no
  option for one, so a node whose clock lags the realm's refuses a fresh token as issued in the
  future. Keep the clocks in sync; a firewall that must tolerate drift keeps its own authenticator.
- **Concurrent refreshes.** With the realm's *Revoke Refresh Token* on, a refresh token works once:
  two tabs refreshing at the same moment race, and the loser's refresh is refused, which reads as a
  logout. Refresh from one place (a shared promise in the web app), or leave the setting off.
- **Other bearer authenticators on the same firewall** (Lexik, say). Symfony runs every authenticator
  that supports a request, and the `keycloak` one supports every bearer, so its 401 would answer a
  token meant for the other. Give it an extractor that returns only the tokens of its issuers
  (`UnverifiedIssuer::of()`), under `token_extractors`, or verify the other tokens in a decorator of
  `keycloak.token_handler.<firewall>`.

## Develop

CI (`.github/workflows/qa.yml`) runs the tests, PHPStan and the code style on every supported PHP
and Symfony line, the lowest dependencies included, and the integration suite against real Keycloak
servers.

```bash
composer install
vendor/bin/phpunit                    # Unit + Functional: a booted firewall against the stub realm
vendor/bin/phpstan analyse -c phpstan.dist.neon
vendor/bin/php-cs-fixer fix --dry-run --diff
```

The integration suite needs a Keycloak with `tests/Integration/realm.json` imported:

```bash
docker run -d --name keycloak -p 8080:8080 \
    -v "$PWD/tests/Integration/realm.json:/opt/keycloak/data/import/realm.json:ro" \
    quay.io/keycloak/keycloak:26.7.2 start-dev --import-realm
KEYCLOAK_URL=http://localhost:8080 vendor/bin/phpunit --testsuite Integration
```

## Security

Report vulnerabilities privately, see [SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE). Changes are listed in [CHANGELOG.md](CHANGELOG.md).
