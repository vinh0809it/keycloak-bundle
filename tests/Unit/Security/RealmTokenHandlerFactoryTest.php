<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Tests\Unit\Security;

use Vinh0809it\KeycloakBundle\Security\RealmTokenHandlerFactory;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\RS256;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

final class RealmTokenHandlerFactoryTest extends TestCase
{
    /**
     * @return iterable<string, array{string}>
     */
    public static function realms(): iterable
    {
        yield 'without a trailing slash' => ['http://keycloak:8080/realms/customers'];
        yield 'with a trailing slash' => ['http://keycloak:8080/realms/customers/'];
    }

    public function testARealmWithoutAUrlIsNotConfigured(): void
    {
        $handler = RealmTokenHandlerFactory::create(new AlgorithmManager([new RS256()]), new MockHttpClient(), new ArrayAdapter(), 'key', [['url' => '', 'issuer' => '']], 'api');

        $this->expectException(BadCredentialsException::class);
        $handler->getUserBadgeFrom('a.b.c');
    }

    public function testAnUnconfiguredRealmNamesNoIssuer(): void
    {
        self::assertSame(['https://sso/realms/a'], RealmTokenHandlerFactory::issuers([['url' => 'http://kc/realms/a', 'issuer' => 'https://sso/realms/a'], ['url' => '', 'issuer' => '']]));
    }

    public function testAnExplicitIssuerIsTakenAsWrittenAndOneFromTheUrlHasNoTrailingSlash(): void
    {
        self::assertSame('https://tenant.idp.test/', RealmTokenHandlerFactory::issuer(['url' => 'https://tenant.idp.test/', 'issuer' => 'https://tenant.idp.test/']));
        self::assertSame('http://kc/realms/a', RealmTokenHandlerFactory::issuer(['url' => 'http://kc/realms/a/', 'issuer' => null]));
    }

    #[DataProvider('realms')]
    public function testDiscoveryResolvesUnderTheRealmPath(string $realm): void
    {
        $requested = [];
        $http = new MockHttpClient(static function (string $method, string $url) use (&$requested): MockResponse {
            $requested[] = $url;

            return new MockResponse('{}', ['http_code' => 500]);
        });

        $handler = RealmTokenHandlerFactory::create(new AlgorithmManager([new RS256()]), $http, new ArrayAdapter(), 'key', [['url' => $realm, 'issuer' => null]], 'api');

        try {
            $handler->getUserBadgeFrom('a.b.c');
        } catch (\Throwable) {
            // Discovery fails against the 500 above; only the URL it asked for matters here.
        }

        self::assertSame('http://keycloak:8080/realms/customers/.well-known/openid-configuration', $requested[0] ?? null);
    }

    public function testSeveralProvidersWithoutPerIssuerKeysAreWarnedAboutOncePerProcess(): void
    {
        (new \ReflectionProperty(RealmTokenHandlerFactory::class, 'warned'))->setValue(null, false);
        $logger = new class () extends AbstractLogger {
            /** @var list<string> */
            public array $warnings = [];

            public function log($level, \Stringable|string $message, array $context = []): void
            {
                $this->warnings[] = (string) $level;
            }
        };
        $realms = [['url' => 'http://kc/realms/a', 'issuer' => null]];
        $other = [['url' => 'https://other.test', 'issuer' => null]];

        RealmTokenHandlerFactory::create(new AlgorithmManager([new RS256()]), new MockHttpClient(), new ArrayAdapter(), 'key', $realms, 'api', $logger, [], false);
        self::assertSame([], $logger->warnings, 'one provider has no other to be confused with');

        RealmTokenHandlerFactory::create(new AlgorithmManager([new RS256()]), new MockHttpClient(), new ArrayAdapter(), 'key', $realms, 'api', $logger, $other, true);
        self::assertSame([], $logger->warnings, 'Symfony binds each provider\'s keys to its issuer');

        RealmTokenHandlerFactory::create(new AlgorithmManager([new RS256()]), new MockHttpClient(), new ArrayAdapter(), 'key', $realms, 'api', $logger, $other, false);
        RealmTokenHandlerFactory::create(new AlgorithmManager([new RS256()]), new MockHttpClient(), new ArrayAdapter(), 'key', $realms, 'api', $logger, $other, false);
        self::assertSame(['warning'], $logger->warnings);
    }
}
