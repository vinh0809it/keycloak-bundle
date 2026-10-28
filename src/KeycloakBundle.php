<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle;

use Vinh0809it\KeycloakBundle\Client\KeycloakClient;
use Vinh0809it\KeycloakBundle\Client\ServiceToken;
use Vinh0809it\KeycloakBundle\DependencyInjection\KeycloakAuthenticatorFactory;
use Vinh0809it\KeycloakBundle\DependencyInjection\ResolveRealmsPass;
use Vinh0809it\KeycloakBundle\Security\CookieTokenExtractor;
use Vinh0809it\KeycloakBundle\Security\RealmTokenHandlerFactory;
use Jose\Component\Core\AlgorithmManager;
use Vinh0809it\KeycloakBundle\Session\CookieOptions;
use Vinh0809it\KeycloakBundle\Session\SessionCookies;
use Symfony\Bundle\SecurityBundle\DependencyInjection\SecurityExtension;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;
use Symfony\Component\Security\Http\AccessToken\HeaderAccessTokenExtractor;

/**
 * Keycloak realms, declared once: trusting their tokens, and calling them.
 *
 * A realm is any OpenID provider with discovery: a Keycloak realm, or a service's own issuer of
 * legacy tokens. `realm:` + `issuer:` at the root is the one-realm shorthand for
 * `realms: { default: { url, issuer } }`.
 *
 * Trusting tokens is a firewall's `keycloak` authenticator ({@see KeycloakAuthenticatorFactory}),
 * configured in security.yaml with what is the firewall's own: the realms it accepts, the resolver
 * per client, whether the token may ride in the access cookie. What is the realm's stays here.
 *
 *  - `keycloak.token_extractor.header` / `.cookie`: the `Authorization: Bearer` header, and
 *    the access cookie when `cookies` is set.
 *  - `keycloak.session_cookies`: when `cookies` is set, the {@see SessionCookies} a
 *    backend-for-frontend sets and clears the session with.
 *  - `keycloak.client.<name>`: a {@see KeycloakClient} of its realm per entry under
 *    `clients`, and `keycloak.service_token.<name>` for one with a secret.
 *  - `dev_tokens`: literal bearers in front of every keycloak firewall's verifier, answering with
 *    configured claims. Refused in `prod`.
 *
 * ```yaml
 * keycloak:
 *     realm: '%env(KEYCLOAK_BASE_URI)%'       # or realms: { customers: {url, issuer}, employees: {...} }
 *     issuer: '%env(KEYCLOAK_ISSUER)%'
 *     audience: my-api
 *     cookies:
 *         access: { name: app_at, domain: '%env(WEB_COOKIE_DOMAIN)%' }
 *         refresh: { name: app_rt, path: /web, same_site: strict }
 *     clients:
 *         service: { id: my-api, secret: '%env(MY_API_CLIENT_SECRET)%' }
 * ```
 */
final class KeycloakBundle extends AbstractBundle
{
    /** The realm a one-realm configuration (`realm:` at the root) declares. */
    public const string DEFAULT_REALM = 'default';

    /*
     * The ids of the services this bundle registers. A prefix ending in a dot takes the firewall's
     * or client's name after it.
     */

    /** + firewall name: the `keycloak` authenticator. */
    public const string AUTHENTICATOR = 'keycloak.authenticator.';
    /** + firewall name: the firewall's `oidc` access-token handler. */
    public const string TOKEN_HANDLER = 'keycloak.token_handler.';
    /** + firewall name: the firewall's user provider. */
    public const string USER_PROVIDER = 'keycloak.user_provider.';
    /** + firewall name: the dev-token decorator of the firewall's handler. */
    public const string DEV_TOKEN_HANDLER = 'keycloak.dev_token_handler.';
    /** + client name: the {@see KeycloakClient}. */
    public const string CLIENT = 'keycloak.client.';
    /** + client name: the confidential client's {@see ServiceToken}. */
    public const string SERVICE_TOKEN = 'keycloak.service_token.';
    public const string TOKEN_EXTRACTOR_HEADER = 'keycloak.token_extractor.header';
    public const string TOKEN_EXTRACTOR_COOKIE = 'keycloak.token_extractor.cookie';
    public const string SESSION_COOKIES = 'keycloak.session_cookies';
    public const string SIGNATURE_ALGORITHMS = 'keycloak.signature_algorithms';
    public const string HTTP_CLIENT = 'keycloak.http_client';
    public const string DISCOVERY_CACHE = 'keycloak.discovery_cache';

    /** What {@see ResolveRealmsPass} completes the firewalls' handlers with. */
    public const string REALMS_PARAMETER = '.keycloak.realms';
    public const string AUDIENCE_PARAMETER = '.keycloak.audience';
    public const string DEV_TOKENS_PARAMETER = '.keycloak.dev_tokens';

    /** Where a firewall's handler caches its realms' discovered configuration and keys. */
    public static function discoveryCacheKey(string $firewall): string
    {
        return self::TOKEN_HANDLER.$firewall.'.oidc_configuration';
    }

    /**
     * The realm $name names, or the only one declared when $name is null.
     *
     * @param array<string, array{url: string, issuer: ?string}> $realms
     */
    public static function realmName(array $realms, ?string $name, string $path): string
    {
        if (null === $name) {
            if (1 !== \count($realms)) {
                throw new InvalidConfigurationException(\sprintf('%s must name its realm: %s.', $path, [] === $realms ? 'none is declared under keycloak' : 'several are declared'));
            }

            return (string) array_key_first($realms);
        }
        if (!isset($realms[$name])) {
            throw new InvalidConfigurationException(\sprintf('%s names the realm "%s", which keycloak does not declare.', $path, $name));
        }

        return $name;
    }

    public function build(ContainerBuilder $container): void
    {
        $security = $container->hasExtension('security') ? $container->getExtension('security') : null;
        if (!$security instanceof SecurityExtension) {
            throw new \LogicException('KeycloakBundle needs SecurityBundle, registered before it in config/bundles.php.');
        }
        $security->addAuthenticatorFactory(new KeycloakAuthenticatorFactory());
        $container->addCompilerPass(new ResolveRealmsPass());
    }

    public function configure(DefinitionConfigurator $definition): void
    {
        $definition->rootNode()
            ->children()
                ->scalarNode('realm')
                    ->info('One-realm shorthand: the realm URL this service reaches Keycloak at, e.g. http://keycloak:8080/realms/customers. Declares the realm "default".')
                    ->defaultNull()
                ->end()
                ->scalarNode('issuer')
                    ->info('One-realm shorthand: the realm URL as tokens name it in `iss`, when it differs from `realm` (a public host).')
                    ->defaultNull()
                ->end()
                ->arrayNode('realms')
                    ->info('Realms by name: every OpenID provider whose tokens a firewall accepts or whose clients this service calls as.')
                    ->useAttributeAsKey('name')
                    ->arrayPrototype()
                        ->children()
                            ->scalarNode('url')
                                ->info('The realm URL this service reaches it at. A trailing slash is optional.')
                                ->isRequired()
                                ->cannotBeEmpty()
                            ->end()
                            ->scalarNode('issuer')
                                ->info('The realm URL as tokens name it in `iss` and browsers reach it at, when it differs from `url`.')
                                ->defaultNull()
                            ->end()
                        ->end()
                    ->end()
                ->end()
                ->scalarNode('audience')
                    ->info('The `aud` a token must carry to be accepted, for every keycloak firewall that does not set its own.')
                    ->defaultNull()
                ->end()
                ->arrayNode('algorithms')
                    ->info('Signature algorithms accepted on access tokens.')
                    ->enumPrototype()->values(RealmTokenHandlerFactory::ALGORITHMS)->end()
                    ->defaultValue(['RS256'])
                    ->requiresAtLeastOneElement()
                ->end()
                ->scalarNode('discovery_cache')
                    ->info('Cache pool holding the realms\' discovered configuration and keys.')
                    ->defaultValue('cache.app')
                ->end()
                ->scalarNode('http_client')
                    ->info('HTTP client service for discovery and every client below.')
                    ->defaultValue('http_client')
                ->end()
                ->arrayNode('dev_tokens')
                    ->info('Literal bearer => the claims it stands for (sub defaults to the bearer), on every keycloak firewall. Never in prod.')
                    ->normalizeKeys(false)
                    ->useAttributeAsKey('token')
                    ->variablePrototype()->end()
                ->end()
                ->arrayNode('cookies')
                    ->info('The session cookies of a backend-for-frontend; registers keycloak.token_extractor.cookie and keycloak.session_cookies.')
                    ->canBeUnset()
                    ->children()
                        ->append(self::cookieNode('access', '/', 'lax')->isRequired())
                        ->append(self::cookieNode('refresh', '/', 'strict')
                            ->canBeUnset()
                            ->children()
                                ->scalarNode('session_lifetime')
                                    ->info('Seconds a refresh token Keycloak gives no expiry (refresh_expires_in 0) is kept; null for a browser-session cookie.')
                                    ->defaultValue(1209600)
                                    ->validate()
                                        ->ifTrue(static fn (mixed $v): bool => null !== $v && (!\is_int($v) || $v <= 0))
                                        ->thenInvalid('session_lifetime must be a positive number of seconds, or null.')
                                    ->end()
                                ->end()
                            ->end())
                    ->end()
                ->end()
                ->arrayNode('clients')
                    ->info('Keycloak clients this service calls a realm as; registers keycloak.client.<name>, and keycloak.service_token.<name> for a confidential one.')
                    ->normalizeKeys(false)
                    ->useAttributeAsKey('name')
                    ->arrayPrototype()
                        ->children()
                            ->scalarNode('realm')
                                ->info('The realm the client belongs to; may be left out when only one realm is declared.')
                                ->defaultNull()
                            ->end()
                            ->scalarNode('id')
                                ->info('The Keycloak client id. Defaults to the entry\'s name.')
                                ->defaultNull()
                            ->end()
                            ->scalarNode('secret')
                                ->info('The client secret; leave unset for a public client.')
                                ->defaultNull()
                            ->end()
                            ->scalarNode('token_cache')
                                ->info('Cache pool sharing the service token across requests and workers (cache.app, say); unset, it lives only as long as the service.')
                                ->defaultNull()
                            ->end()
                        ->end()
                    ->end()
                ->end()
            ->end();
    }

    /**
     * @param array{
     *     realm: ?string,
     *     issuer: ?string,
     *     realms: array<string, array{url: string, issuer: ?string}>,
     *     audience: ?string,
     *     algorithms: list<string>,
     *     discovery_cache: string,
     *     http_client: string,
     *     dev_tokens: array<string, array<string, mixed>>,
     *     cookies?: array{access: array{name: string, path: string, domain: ?string, same_site: string}, refresh?: array{name: string, path: string, domain: ?string, same_site: string, session_lifetime: ?int}},
     *     clients: array<string, array{realm: ?string, id: ?string, secret: ?string, token_cache: ?string}>
     * } $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $realms = $config['realms'];
        if (null !== $config['realm']) {
            if (isset($realms[self::DEFAULT_REALM])) {
                throw new InvalidConfigurationException('keycloak: declare the realm "default" either with "realm" at the root or under "realms", not both.');
            }
            $realms[self::DEFAULT_REALM] = ['url' => $config['realm'], 'issuer' => $config['issuer']];
        } elseif (null !== $config['issuer']) {
            throw new InvalidConfigurationException('keycloak.issuer belongs with keycloak.realm; under "realms", set each realm\'s own issuer.');
        }
        if ([] !== $config['dev_tokens'] && ('prod' === $builder->getParameter('kernel.environment') || !$builder->getParameter('kernel.debug'))) {
            throw new InvalidConfigurationException('keycloak.dev_tokens cannot be set in the prod environment, nor with debug off.');
        }

        $builder->setParameter(self::REALMS_PARAMETER, $realms);
        $builder->setParameter(self::AUDIENCE_PARAMETER, $config['audience']);
        $builder->setParameter(self::DEV_TOKENS_PARAMETER, $config['dev_tokens']);

        $builder->setAlias(self::HTTP_CLIENT, $config['http_client']);
        $builder->setAlias(self::DISCOVERY_CACHE, $config['discovery_cache']);
        // Symfony's own algorithm manager for the `oidc` handler (SecurityBundle).
        $builder->register(self::SIGNATURE_ALGORITHMS, AlgorithmManager::class)
            ->setFactory([RealmTokenHandlerFactory::class, 'algorithms'])
            ->setArguments([$config['algorithms']]);

        $builder->register(self::TOKEN_EXTRACTOR_HEADER, HeaderAccessTokenExtractor::class);
        if (isset($config['cookies'])) {
            $access = $config['cookies']['access'];
            $refresh = $config['cookies']['refresh'] ?? null;
            $builder->register(self::TOKEN_EXTRACTOR_COOKIE, CookieTokenExtractor::class)
                ->setArguments([$access['name']]);
            $builder->register(self::SESSION_COOKIES, SessionCookies::class)
                ->setArguments([
                    self::cookieOptions($access),
                    null !== $refresh ? self::cookieOptions($refresh) : null,
                    $refresh['session_lifetime'] ?? null,
                ]);
        }

        foreach ($config['clients'] as $name => $client) {
            $realm = $realms[self::realmName($realms, $client['realm'], 'keycloak.clients.'.$name)];
            $builder->register(self::CLIENT.$name, KeycloakClient::class)
                ->setArguments([
                    new Reference(self::HTTP_CLIENT),
                    $realm['url'],
                    $client['id'] ?? $name,
                    $client['secret'],
                    $realm['issuer'],
                ]);

            if (null !== $client['secret']) {
                $builder->register(self::SERVICE_TOKEN.$name, ServiceToken::class)
                    ->setArguments([
                        '$client' => new Reference(self::CLIENT.$name),
                        '$cache' => null !== $client['token_cache'] ? new Reference($client['token_cache']) : null,
                        '$cacheKey' => self::SERVICE_TOKEN.$name,
                    ]);
            }
        }
    }

    private static function cookieNode(string $name, string $path, string $sameSite): ArrayNodeDefinition
    {
        return (new ArrayNodeDefinition($name))
            ->children()
                ->scalarNode('name')->isRequired()->cannotBeEmpty()->end()
                ->scalarNode('path')->defaultValue($path)->end()
                ->scalarNode('domain')
                    ->info('Empty or unset: host-only.')
                    ->defaultNull()
                ->end()
                ->scalarNode('same_site')->defaultValue($sameSite)->end()
            ->end();
    }

    /**
     * @param array{name: string, path: string, domain: ?string, same_site: string} $cookie
     */
    private static function cookieOptions(array $cookie): Definition
    {
        return new Definition(CookieOptions::class, [$cookie['name'], $cookie['path'], $cookie['domain'], $cookie['same_site']]);
    }
}
