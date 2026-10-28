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
| PHP | 8.3+ | 8.3, 8.4, 8.5 |
| Symfony | 7.4.20+, 8.1.8+ | 7.4 (lowest and latest dependencies), 8.1 |
| Keycloak | 26 | 26.5, 26.7, against a real server |

The Symfony floor is `symfony/security-http` 7.4.20 / 8.1.8: earlier releases (8.0 included) pool the
keys of every discovered provider, so with several realms a token signed by one realm could claim
another's issuer. From those releases on, each provider's keys verify only tokens naming that
provider as `iss`.

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

- **The `keycloak` authenticator** of a firewall: Symfony's access-token authenticator, verifying the
  bearer against the realms that firewall accepts, then turning the verified claims into the app's
  principal through a `ClaimsResolverInterface` chosen by the token's `azp` (the Keycloak client it
  was minted for) or the firewall's default. A realm URL works with or without a trailing slash, and
  its issuer defaults to it. Across several realms, each realm's keys verify only tokens whose `iss`
  is that realm's. It brings its own user provider.
- **`keycloak.token_extractor.header`** and, when `cookies` is set,
  **`keycloak.token_extractor.cookie`**: where a firewall finds the token, the
  `Authorization: Bearer` header (Symfony's own extractor) and the access cookie. The firewall
  lists them in the order it tries them.
- **`keycloak.session_cookies`**, when `cookies` is set: a backend-for-frontend's session.
  `set(Response, TokenSet)` writes the access and refresh cookies (HttpOnly, Secure, expiring with
  their tokens), `clear(Response)` ends them, `refreshToken(Request)` reads the refresh token. The
  login flow itself (routes, PKCE state) stays the app's.
- **`dev_tokens`**: literal bearers for local development (`user.1`, `admin.2`) answering with
  configured claims, through the same resolvers as a real token. Refused in `prod`.
- **`keycloak.client.<name>`** for each entry under `clients`, and
  **`keycloak.service_token.<name>`** for one with a secret. Nothing is registered when
  `clients` is empty. See *Calling the realm*.
- **`Vinh0809it\KeycloakBundle\Test\KeycloakStub`**: the realm for a test suite. Discovery, a JWKS the real
  verifier checks against, signed tokens, the client-credentials grant, and hooks for the app's own
  grants (`grant()`) and SPI endpoints (`on()`).

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
    # algorithms: [RS256]                    # RS*, PS* or ES*; anything else is refused

when@dev:
    keycloak:
        dev_tokens:                          # on every keycloak firewall; refused in prod and with debug off
            'user.1': { azp: mobile-app, username: 'user@example.com' }
```

```yaml
# config/packages/security.yaml: each firewall's own part
security:
    firewalls:
        main:
            stateless: true
            keycloak:
                resolver: App\Security\MemberResolver
                by_client:                   # optional: azp => resolver
                    admin-web: App\Security\AdminResolver
                cookie: true                 # optional: also read the access cookie, after the header
                # token_extractors: [keycloak.token_extractor.header, App\Security\OriginCookieExtractor]
                #                            # instead of cookie: extractor ids, tried in order
                # realms: [customers]         # with several realms
                # audience: ...              # to override keycloak.audience
                # other_issuers: [{ url, issuer, resolver }]   # OpenID providers other than the realms
```

The firewall must be `stateless`: the principal is rebuilt from each request's token and is never
reloaded from a session, so a stateful firewall is a configuration error. No `providers` entry is
needed for it, and the firewall order and the access rules stay the app's.
A decorator of the firewall's token handler (a legacy issuer, say) decorates
`keycloak.token_handler.<firewall>`.

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
  firewall's `other_issuers`, with the resolver of its principals. It is verified by the same
  handler, each provider's keys bound to its own issuer, and resolved by issuer before `by_client`.
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

All three implement `KeycloakException`.

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
        parent::__construct('https://keycloak.test/realms/customers', $cacheDir, $cache);
        $this->serviceClient('my-service', ['sub' => '...', 'azp' => 'my-service', 'aud' => ['other-api']]);
    }

    public function bearerFor(User $user): string
    {
        return $this->sign(['sub' => '...', 'azp' => 'mobile-app', 'aud' => 'my-api', 'username' => '...']);
    }
}
```

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
