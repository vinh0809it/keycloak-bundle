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
    private const REALM = ['realm' => '%env(KEYCLOAK_BASE_URI)%', 'audience' => 'my-api'];

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
        $container = self::build('dev', self::REALM + ['cookies' => ['access' => ['name' => 'at']]], [
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
        self::assertEquals(new Reference(KeycloakBundle::TOKEN_HANDLER.'main'), $main->getArgument('$accessTokenHandler'));
        self::assertEquals(new Reference(KeycloakBundle::USER_PROVIDER.'main'), $main->getArgument('$userProvider'));

        $chain = $container->getDefinition((string) $main->getArgument('$accessTokenExtractor'));
        self::assertEquals([new Reference(KeycloakBundle::TOKEN_EXTRACTOR_HEADER), new Reference(KeycloakBundle::TOKEN_EXTRACTOR_COOKIE)], $chain->getArgument(0), 'the bearer header first, then the cookie');
        self::assertEquals(new Reference(KeycloakBundle::TOKEN_EXTRACTOR_HEADER), $container->getDefinition(KeycloakBundle::AUTHENTICATOR.'api')->getArgument('$accessTokenExtractor'), 'no cookie: the header alone');
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

        $chain = $container->getDefinition((string) $container->getDefinition(KeycloakBundle::AUTHENTICATOR.'main')->getArgument('$accessTokenExtractor'));
        self::assertEquals([new Reference(KeycloakBundle::TOKEN_EXTRACTOR_HEADER), new Reference('app.origin_cookie_extractor')], $chain->getArgument(0));
        self::assertEquals(new Reference('app.only_extractor'), $container->getDefinition(KeycloakBundle::AUTHENTICATOR.'api')->getArgument('$accessTokenExtractor'), 'one extractor needs no chain');
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

    public function testADevTokenPatternThatCouldTakeAJwtIsRefused(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('{azp}~{sub}');

        self::build('dev', self::REALM + ['dev_tokens' => ['user.{sub}' => []]]);
    }

    /** @return iterable<string, array{array<string, mixed>, string}> */
    public static function badDevTokens(): iterable
    {
        yield 'claims that are not a map' => [['user.1' => 'admin'], 'map of claims'];
        yield 'a placeholder named twice' => [['{sub}~{sub}' => []], 'twice'];
        yield 'a placeholder starting with a digit' => [['{1}~{sub}' => []], 'not starting with a digit'];
    }

    /** @param array<string, mixed> $tokens */
    #[DataProvider('badDevTokens')]
    public function testADevTokenTheHandlerCouldNotServeIsRefused(array $tokens, string $message): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage($message);

        self::build('dev', self::REALM + ['dev_tokens' => $tokens]);
    }

    public function testADevTokenWithNoClaimsStandsForNone(): void
    {
        $container = self::build('dev', self::REALM + ['dev_tokens' => ['user.1' => null]], ['main' => ['resolver' => 'r']]);

        self::assertSame(['user.1' => []], $container->getDefinition(KeycloakBundle::DEV_TOKEN_HANDLER.'main')->getArgument(1));
    }

    public function testRealmNamesAreKeptVerbatim(): void
    {
        $container = self::build('dev', [
            'audience' => 'shop-api',
            'realms' => ['my-realm' => ['url' => 'http://kc/realms/my-realm'], 'other' => ['url' => 'http://kc/realms/other']],
            'clients' => ['web' => ['realm' => 'my-realm']],
        ], ['main' => ['realms' => ['my-realm', 'other'], 'by_realm' => ['my-realm' => 'app.resolver']]]);

        self::assertSame([['url' => 'http://kc/realms/my-realm', 'issuer' => null]], [$container->getDefinition(KeycloakBundle::USER_PROVIDER.'main')->getArgument(2)[0]['provider']]);
    }

    public function testTheRefreshCookiesLifetimeMayComeFromTheEnvironment(): void
    {
        $container = self::build('dev', self::REALM + ['cookies' => ['access' => ['name' => 'at'], 'refresh' => ['name' => 'rt', 'session_lifetime' => '%env(int:RT_LIFETIME)%']]]);

        self::assertSame('%env(int:RT_LIFETIME)%', $container->getDefinition(KeycloakBundle::SESSION_COOKIES)->getArgument(2));
    }

    public function testACookieSameSitePolicyMustBeOneBrowsersKnow(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('same_site');

        self::build('dev', self::REALM + ['cookies' => ['access' => ['name' => 'at', 'same_site' => 'loose']]]);
    }

    public function testReadingTheCookieNeedsItsName(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('keycloak.cookies.access');

        self::build('dev', self::REALM, ['main' => ['resolver' => 'r', 'cookie' => true]]);
    }

    public function testEachClientHasABrowserLoginWithItsOwnCookie(): void
    {
        $container = self::build('dev', self::REALM + ['clients' => [
            'web' => [],
            'admin' => ['login_cookie' => ['name' => 'admin_login', 'path' => '/admin', 'domain' => 'app.test'], 'return_origins' => ['https://admin.app.test']],
        ]]);

        $web = $container->getDefinition(KeycloakBundle::BROWSER_LOGIN.'web');
        self::assertEquals(new Reference(KeycloakBundle::CLIENT.'web'), $web->getArgument(0));
        self::assertSame(['keycloak_login_web', '/', null, 'lax'], $web->getArgument(1)->getArguments());
        self::assertSame('%kernel.secret%', $web->getArgument(2), 'the login cookie is signed with the app\'s secret');
        self::assertSame([], $web->getArgument(3), 'only this app\'s own paths by default');
        $admin = $container->getDefinition(KeycloakBundle::BROWSER_LOGIN.'admin');
        self::assertSame(['admin_login', '/admin', 'app.test', 'lax'], $admin->getArgument(1)->getArguments());
        self::assertSame(['https://admin.app.test'], $admin->getArgument(3));
    }

    public function testTheFirewallsHandlersAreWrappedAsSecurityBundleWrapsItsOwn(): void
    {
        $container = self::build('dev', self::REALM, ['main' => ['resolver' => 'r', 'success_handler' => 'app.on_success', 'failure_handler' => 'app.on_failure']]);
        $authenticator = $container->getDefinition(KeycloakBundle::AUTHENTICATOR.'main');

        $success = $container->getDefinition((string) $authenticator->getArgument('$successHandler'));
        \assert($success instanceof ChildDefinition);
        self::assertSame('security.authentication.custom_success_handler', $success->getParent());
        self::assertEquals([new Reference('app.on_success'), [], 'main'], array_values($success->getArguments()));

        $failure = $container->getDefinition((string) $authenticator->getArgument('$failureHandler'));
        \assert($failure instanceof ChildDefinition);
        self::assertSame('security.authentication.custom_failure_handler', $failure->getParent());
        self::assertEquals([new Reference('app.on_failure'), []], array_values($failure->getArguments()));

        self::assertNull(self::build('dev', self::REALM, ['main' => ['resolver' => 'r']])->getDefinition(KeycloakBundle::AUTHENTICATOR.'main')->getArgument('$failureHandler'));
    }

    public function testARealmsResolverIsMatchedByThatRealmsIssuer(): void
    {
        $container = self::build('dev', [
            'audience' => 'shop-api',
            'realms' => [
                'customers' => ['url' => 'http://kc/realms/customers', 'issuer' => 'https://sso/realms/customers'],
                'employees' => ['url' => 'http://kc/realms/employees'],
            ],
        ], ['main' => ['realms' => ['customers', 'employees'], 'by_realm' => ['employees' => 'app.staff_resolver']]]);

        self::assertEquals(
            [['provider' => ['url' => 'http://kc/realms/employees', 'issuer' => null], 'resolver' => new Reference('app.staff_resolver')]],
            $container->getDefinition(KeycloakBundle::USER_PROVIDER.'main')->getArgument(2),
        );
    }

    public function testARealmTheFirewallDoesNotAcceptCannotHaveAResolverThere(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('not one of the firewall\'s realms');

        self::build('dev', [
            'audience' => 'shop-api',
            'realms' => ['customers' => ['url' => 'http://kc/realms/customers'], 'employees' => ['url' => 'http://kc/realms/employees']],
        ], ['main' => ['realms' => ['customers'], 'resolver' => 'r', 'by_realm' => ['employees' => 'app.staff_resolver']]]);
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
