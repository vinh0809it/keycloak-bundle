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

        // Never reached in practice: the keycloak authenticator takes no token for a realm without a URL.
        $this->expectException(\LogicException::class);
        $handler->getUserBadgeFrom('a.b.c');
    }

    public function testAnUnconfiguredRealmNamesNoIssuer(): void
    {
        self::assertSame(['https://sso/realms/a'], RealmTokenHandlerFactory::issuers([['url' => 'http://kc/realms/a', 'issuer' => 'https://sso/realms/a/'], ['url' => '', 'issuer' => '']]));
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
}
