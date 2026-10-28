<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Tests\Unit;

use Vinh0809it\KeycloakBundle\Client\KeycloakClient;
use Vinh0809it\KeycloakBundle\DependencyInjection\KeycloakAuthenticatorFactory;
use Vinh0809it\KeycloakBundle\DependencyInjection\ResolveRealmsPass;
use Vinh0809it\KeycloakBundle\KeycloakBundle;
use Vinh0809it\KeycloakBundle\Security\ClaimsUserProvider;
use Vinh0809it\KeycloakBundle\Security\CookieTokenExtractor;
use Vinh0809it\KeycloakBundle\Security\DevTokenHandler;
use Vinh0809it\KeycloakBundle\Security\RealmTokenHandlerFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\Security\Http\AccessToken\HeaderAccessTokenExtractor;
use Symfony\Component\Security\Http\Authenticator\AccessTokenAuthenticator;

final class KeycloakBundleTest extends TestCase
{
    private const array REALM = ['realm' => '%env(KEYCLOAK_BASE_URI)%', 'audience' => 'my-api'];

    public function testTheOneRealmShorthandIsTheRealmAKeycloakFirewallAccepts(): void
    {
        $container = self::build('dev', self::REALM + ['issuer' => 'https://sso.example/realms/customers'], ['main' => ['resolver' => 'r']]);

        $handler = $container->getDefinition(KeycloakBundle::TOKEN_HANDLER.'main');
        self::assertSame([RealmTokenHandlerFactory::class, 'create'], $handler->getFactory());
        self::assertEquals(new Reference(KeycloakBundle::DISCOVERY_CACHE), $handler->getArgument('$discoveryCache'));
        self::assertSame('cache.app', (string) $container->getAlias(KeycloakBundle::DISCOVERY_CACHE));
        self::assertSame(KeycloakBundle::discoveryCacheKey('main'), $handler->getArgument('$cacheKey'));
        self::assertSame([['url' => '%env(KEYCLOAK_BASE_URI)%', 'issuer' => 'https://sso.example/realms/customers']], $handler->getArgument('$realms'), 'URLs are normalised at runtime, once their env vars are resolved');
        self::assertSame('my-api', $handler->getArgument('$audience'));
    }

    public function testEachFirewallAcceptsTheRealmsItNames(): void
    {
        $container = self::build('dev', [
            'audience' => 'shop-api',
            'realms' => [
                'customers' => ['url' => 'http://kc/realms/customers', 'issuer' => 'https://sso/realms/customers'],
                'employees' => ['url' => 'http://kc/realms/employees'],
            ],
        ], [
            'customer' => ['realms' => ['customers'], 'resolver' => 'r'],
            'staff' => ['realms' => ['employees'], 'audience' => 'shop-api-staff', 'resolver' => 'r'],
            'sso' => ['realms' => ['customers', 'employees'], 'resolver' => 'r'],
        ]);

        self::assertSame([['url' => 'http://kc/realms/customers', 'issuer' => 'https://sso/realms/customers']], $container->getDefinition(KeycloakBundle::TOKEN_HANDLER.'customer')->getArgument('$realms'));
        self::assertSame([['url' => 'http://kc/realms/employees', 'issuer' => null]], $container->getDefinition(KeycloakBundle::TOKEN_HANDLER.'staff')->getArgument('$realms'));
        self::assertSame('shop-api-staff', $container->getDefinition(KeycloakBundle::TOKEN_HANDLER.'staff')->getArgument('$audience'), 'a firewall may set its own audience');
        self::assertCount(2, $container->getDefinition(KeycloakBundle::TOKEN_HANDLER.'sso')->getArgument('$realms'));
        self::assertSame('shop-api', $container->getDefinition(KeycloakBundle::TOKEN_HANDLER.'sso')->getArgument('$audience'));
    }

    public function testTheAuthenticatorBringsItsOwnProviderAndReadsTheCookieWhenAsked(): void
    {
        $container = self::build('dev', self::REALM, [
            'main' => ['resolver' => 'app.member_resolver', 'by_client' => ['admin-web' => 'app.admin_resolver'], 'cookie' => true],
            'api' => ['by_client' => ['admin-web' => 'app.admin_resolver']],
        ]);

        $provider = $container->getDefinition(KeycloakBundle::USER_PROVIDER.'main');
        self::assertSame(ClaimsUserProvider::class, $provider->getClass());
        self::assertEquals(new Reference('app.member_resolver'), $provider->getArgument(0));
        self::assertEquals(['admin-web' => new Reference('app.admin_resolver')], $provider->getArgument(1), 'client ids are kept verbatim');
        self::assertNull($container->getDefinition(KeycloakBundle::USER_PROVIDER.'api')->getArgument(0));

        $main = $container->getDefinition(KeycloakBundle::AUTHENTICATOR.'main');
        self::assertSame(AccessTokenAuthenticator::class, $main->getClass(), "Symfony's own authenticator, built from its public class");
        self::assertEquals(new Reference(KeycloakBundle::TOKEN_HANDLER.'main'), $main->getArgument(0));
        self::assertEquals(new Reference(KeycloakBundle::USER_PROVIDER.'main'), $main->getArgument(2));

        $chain = $container->getDefinition((string) $main->getArgument(1));
        self::assertEquals([new Reference(KeycloakBundle::TOKEN_EXTRACTOR_HEADER), new Reference(KeycloakBundle::TOKEN_EXTRACTOR_COOKIE)], $chain->getArgument(0), 'the bearer header first, then the cookie');
        self::assertEquals(new Reference(KeycloakBundle::TOKEN_EXTRACTOR_HEADER), $container->getDefinition(KeycloakBundle::AUTHENTICATOR.'api')->getArgument(1), 'no cookie: the header alone');
        self::assertSame(HeaderAccessTokenExtractor::class, $container->getDefinition(KeycloakBundle::TOKEN_EXTRACTOR_HEADER)->getClass());
    }

    public function testOtherIssuersAreVerifiedByTheSameHandlerAndResolvedByTheirOwnResolver(): void
    {
        $container = self::build('dev', self::REALM, ['main' => [
            'resolver' => 'app.member_resolver',
            'other_issuers' => [['url' => '%env(LEGACY_BASE_URI)%', 'issuer' => '%env(LEGACY_ISSUER)%', 'resolver' => 'app.legacy_resolver']],
        ]]);

        $legacy = ['url' => '%env(LEGACY_BASE_URI)%', 'issuer' => '%env(LEGACY_ISSUER)%'];
        self::assertSame([$legacy], $container->getDefinition(KeycloakBundle::TOKEN_HANDLER.'main')->getArgument('$otherIssuers'));
        self::assertEquals([['provider' => $legacy, 'resolver' => new Reference('app.legacy_resolver')]], $container->getDefinition(KeycloakBundle::USER_PROVIDER.'main')->getArgument(2));
    }

    public function testExplicitTokenExtractorsAreTriedInTheirOrder(): void
    {
        $container = self::build('dev', self::REALM, [
            'main' => ['resolver' => 'r', 'token_extractors' => [KeycloakBundle::TOKEN_EXTRACTOR_HEADER, 'app.origin_cookie_extractor']],
            'api' => ['resolver' => 'r', 'token_extractors' => ['app.only_extractor']],
        ]);

        $chain = $container->getDefinition((string) $container->getDefinition(KeycloakBundle::AUTHENTICATOR.'main')->getArgument(1));
        self::assertEquals([new Reference(KeycloakBundle::TOKEN_EXTRACTOR_HEADER), new Reference('app.origin_cookie_extractor')], $chain->getArgument(0));
        self::assertEquals(new Reference('app.only_extractor'), $container->getDefinition(KeycloakBundle::AUTHENTICATOR.'api')->getArgument(1), 'one extractor needs no chain');
    }

    public function testCookieAndTokenExtractorsTogetherAreAConfigurationError(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('"cookie" or "token_extractors"');

        self::build('dev', self::REALM, ['main' => ['resolver' => 'r', 'cookie' => true, 'token_extractors' => ['x']]]);
    }

    public function testDevTokensDecorateEveryKeycloakFirewallsHandler(): void
    {
        $container = self::build('test', self::REALM + ['dev_tokens' => ['user.1' => ['azp' => 'mobile-app'], 'dev-token' => []]], [
            'main' => ['resolver' => 'r'],
            'api' => ['resolver' => 'r'],
        ]);

        foreach (['main', 'api'] as $firewall) {
            $decorator = $container->getDefinition(KeycloakBundle::DEV_TOKEN_HANDLER.$firewall);
            self::assertSame(DevTokenHandler::class, $decorator->getClass());
            self::assertSame(KeycloakBundle::TOKEN_HANDLER.$firewall, $decorator->getDecoratedService()[0] ?? null);
            self::assertSame(['user.1' => ['azp' => 'mobile-app'], 'dev-token' => []], $decorator->getArgument(1), 'bearers are matched verbatim');
        }
    }

    public function testNoDevTokensNoDecorator(): void
    {
        $container = self::build('dev', self::REALM, ['main' => ['resolver' => 'r']]);

        self::assertFalse($container->hasDefinition(KeycloakBundle::DEV_TOKEN_HANDLER.'main'));
    }

    public function testDevTokensAreRefusedInProd(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        self::build('prod', self::REALM + ['dev_tokens' => ['user.1' => []]]);
    }

    public function testDevTokensAreRefusedWithDebugOff(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'staging');
        $container->setParameter('kernel.debug', false);
        $container->setParameter('kernel.build_dir', sys_get_temp_dir());
        $container->setParameter('kernel.bundles_metadata', []);

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('debug off');

        (new KeycloakBundle())->getContainerExtension()?->load([self::REALM + ['dev_tokens' => ['user.1' => []]]], $container);
    }

    public function testAStatefulFirewallIsRefused(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'dev');
        $container->setParameter('kernel.debug', true);
        $container->setParameter('kernel.build_dir', sys_get_temp_dir());
        $container->setParameter('kernel.bundles_metadata', []);
        (new KeycloakBundle())->getContainerExtension()?->load([self::REALM], $container);
        // How SecurityExtension declares a firewall that keeps a session.
        $container->setDefinition('security.firewall.map.config.main', (new ChildDefinition('security.firewall.config'))->replaceArgument(4, false));
        (new KeycloakAuthenticatorFactory())->createAuthenticator($container, 'main', self::firewall(['resolver' => 'r']), null);

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('stateless: true');

        (new ResolveRealmsPass())->process($container);
    }

    public function testOnlyAsymmetricSignatureAlgorithmsAreAccepted(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        self::build('dev', self::REALM + ['algorithms' => ['HS256']]);
    }

    public function testAServiceTokenCanBeSharedThroughACachePool(): void
    {
        $container = self::build('dev', self::REALM + ['clients' => ['service' => ['secret' => 's', 'token_cache' => 'cache.app'], 'other' => ['secret' => 's']]]);

        $token = $container->getDefinition(KeycloakBundle::SERVICE_TOKEN.'service');
        self::assertEquals(new Reference('cache.app'), $token->getArgument('$cache'));
        self::assertSame(KeycloakBundle::SERVICE_TOKEN.'service', $token->getArgument('$cacheKey'), 'one key per client');
        self::assertNull($container->getDefinition(KeycloakBundle::SERVICE_TOKEN.'other')->getArgument('$cache'));
    }

    public function testAKeycloakFirewallNeedsAResolverOrAClient(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('needs a "resolver"');

        self::build('dev', self::REALM, ['main' => []]);
    }

    public function testAKeycloakFirewallWithoutKeycloakConfiguredIsAConfigurationError(): void
    {
        $container = new ContainerBuilder();
        (new KeycloakAuthenticatorFactory())->createAuthenticator($container, 'main', self::firewall(['resolver' => 'r']), null);

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('keycloak is not configured');

        (new ResolveRealmsPass())->process($container);
    }

    public function testAClientIsOfTheRealmItNames(): void
    {
        $container = self::build('dev', [
            'realms' => ['customers' => ['url' => 'http://kc/realms/customers', 'issuer' => 'https://sso/realms/customers'], 'employees' => ['url' => 'http://kc/realms/employees']],
            'clients' => ['web' => ['realm' => 'customers', 'secret' => 's']],
        ]);

        self::assertSame(['http://kc/realms/customers', 'web', 's', 'https://sso/realms/customers'], \array_slice($container->getDefinition(KeycloakBundle::CLIENT.'web')->getArguments(), 1));
    }

    /**
     * @return iterable<string, array{array<string, mixed>, array<string, array<string, mixed>>, string}>
     */
    public static function ambiguousRealms(): iterable
    {
        $two = ['a' => ['url' => 'http://kc/realms/a'], 'b' => ['url' => 'http://kc/realms/b']];

        yield 'a firewall without realms, several declared' => [['audience' => 'x', 'realms' => $two], ['main' => ['resolver' => 'r']], 'security.firewalls.main.keycloak must name its realm'];
        yield 'a client without a realm, several declared' => [['realms' => $two, 'clients' => ['web' => []]], [], 'keycloak.clients.web must name its realm'];
        yield 'an undeclared realm' => [['audience' => 'x', 'realms' => $two], ['main' => ['realms' => ['c'], 'resolver' => 'r']], 'names the realm "c"'];
        yield 'no realm at all' => [['audience' => 'x'], ['main' => ['resolver' => 'r']], 'none is declared'];
        yield 'the default realm twice' => [['realm' => 'http://kc/realms/a', 'realms' => ['default' => ['url' => 'http://kc/realms/b']]], [], 'either with "realm"'];
        yield 'an issuer without its realm' => [['issuer' => 'https://sso/realms/a', 'realms' => $two], [], 'belongs with keycloak.realm'];
        yield 'a firewall without an audience' => [['realm' => 'http://kc/realms/a'], ['main' => ['resolver' => 'r']], 'needs an "audience"'];
    }

    /**
     * @param array<string, mixed>                $config
     * @param array<string, array<string, mixed>> $firewalls
     */
    #[DataProvider('ambiguousRealms')]
    public function testAnAmbiguousRealmIsAConfigurationError(array $config, array $firewalls, string $message): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage($message);

        self::build('dev', $config, $firewalls);
    }

    public function testSessionCookiesRegisterTheirExtractorAndService(): void
    {
        $container = self::build('dev', self::REALM + ['cookies' => [
            'access' => ['name' => 'app_at', 'domain' => '%env(WEB_COOKIE_DOMAIN)%'],
            'refresh' => ['name' => 'app_rt', 'path' => '/web', 'session_lifetime' => null],
        ]]);

        $extractor = $container->getDefinition(KeycloakBundle::TOKEN_EXTRACTOR_COOKIE);
        self::assertSame(CookieTokenExtractor::class, $extractor->getClass());
        self::assertSame(['app_at'], $extractor->getArguments(), 'the extractor reads the access cookie');

        [$access, $refresh, $lifetime] = $container->getDefinition(KeycloakBundle::SESSION_COOKIES)->getArguments();
        self::assertSame(['app_at', '/', '%env(WEB_COOKIE_DOMAIN)%', 'lax'], $access->getArguments());
        self::assertSame(['app_rt', '/web', null, 'strict'], $refresh->getArguments());
        self::assertNull($lifetime, 'null: a browser-session cookie');
    }

    public function testNoCookiesNoCookieServices(): void
    {
        $container = self::build('dev', self::REALM);

        self::assertFalse($container->hasDefinition(KeycloakBundle::TOKEN_EXTRACTOR_COOKIE));
        self::assertFalse($container->hasDefinition(KeycloakBundle::SESSION_COOKIES));
    }

    public function testTheRefreshCookieIsOptional(): void
    {
        $container = self::build('dev', self::REALM + ['cookies' => ['access' => ['name' => 'at']]]);

        self::assertNull($container->getDefinition(KeycloakBundle::SESSION_COOKIES)->getArgument(1));
    }

    public function testNoClientsRegisterNothingToCallTheRealmWith(): void
    {
        $container = self::build('dev', self::REALM);

        self::assertSame([], array_filter(array_keys($container->getDefinitions()), static fn (string $id): bool => str_starts_with($id, KeycloakBundle::CLIENT) || str_starts_with($id, KeycloakBundle::SERVICE_TOKEN)));
    }

    public function testEachClientIsRegisteredAndAConfidentialOneGetsAServiceToken(): void
    {
        $container = self::build('dev', self::REALM + ['issuer' => 'https://sso.example/realms/customers', 'clients' => [
            'service' => ['id' => 'my-service', 'secret' => '%env(SERVICE_CLIENT_SECRET)%'],
            'mobile-app' => [],
        ]]);

        $service = $container->getDefinition(KeycloakBundle::CLIENT.'service');
        self::assertSame(KeycloakClient::class, $service->getClass());
        self::assertSame(['%env(KEYCLOAK_BASE_URI)%', 'my-service', '%env(SERVICE_CLIENT_SECRET)%', 'https://sso.example/realms/customers'], \array_slice($service->getArguments(), 1));
        self::assertEquals(new Reference(KeycloakBundle::CLIENT.'service'), $container->getDefinition(KeycloakBundle::SERVICE_TOKEN.'service')->getArgument('$client'));

        self::assertSame('mobile-app', $container->getDefinition(KeycloakBundle::CLIENT.'mobile-app')->getArgument(2), 'the id defaults to the name');
        self::assertFalse($container->hasDefinition(KeycloakBundle::SERVICE_TOKEN.'mobile-app'), 'a public client has no service account');
    }

    /**
     * The container as far as this bundle shapes it: keycloak loaded with $config, a
     * `keycloak` authenticator per firewall in $firewalls, then the pass that completes them.
     *
     * @param array<string, mixed>                $config
     * @param array<string, array<string, mixed>> $firewalls firewall name => its `keycloak` block
     */
    private static function build(string $environment, array $config, array $firewalls = []): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', $environment);
        $container->setParameter('kernel.debug', 'prod' !== $environment);
        $container->setParameter('kernel.build_dir', sys_get_temp_dir());
        $container->setParameter('kernel.bundles_metadata', []);

        $extension = (new KeycloakBundle())->getContainerExtension();
        self::assertNotNull($extension);
        $extension->load([$config], $container);

        $factory = new KeycloakAuthenticatorFactory();
        foreach ($firewalls as $name => $firewall) {
            $factory->createAuthenticator($container, $name, self::firewall($firewall), null);
        }
        (new ResolveRealmsPass())->process($container);

        return $container;
    }

    /**
     * A `keycloak` block as the security configuration hands it over: validated, defaults filled in.
     *
     * @param array<string, mixed> $block
     *
     * @return array{realms: list<string>, audience: ?string, resolver: ?string, by_client: array<string, string>, cookie: bool}
     */
    private static function firewall(array $block): array
    {
        $node = new ArrayNodeDefinition('keycloak');
        (new KeycloakAuthenticatorFactory())->addConfiguration($node);

        /* @var array{realms: list<string>, audience: ?string, resolver: ?string, by_client: array<string, string>, cookie: bool} */
        return (new Processor())->process($node->getNode(true), [$block]);
    }
}
