<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Tests\Unit\Test;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Vinh0809it\KeycloakBundle\Client\KeycloakClient;
use Vinh0809it\KeycloakBundle\Test\KeycloakStub;
use Vinh0809it\KeycloakBundle\Test\KeycloakStubRouter;

final class KeycloakStubRouterTest extends TestCase
{
    private KeycloakStub $customers;
    private KeycloakStub $employees;
    private MockHttpClient $http;

    protected function setUp(): void
    {
        KeycloakStub::reset();
        $dir = sys_get_temp_dir().'/keycloak-bundle-test/router';
        $root = new KeycloakStub('https://idp.test', $dir, new ArrayAdapter());
        $this->customers = new KeycloakStub('https://idp.test/realms/customers', $dir, new ArrayAdapter());
        $this->employees = new KeycloakStub('https://idp.test/realms/employees', $dir, new ArrayAdapter());
        $this->http = new MockHttpClient(new KeycloakStubRouter($root, $this->customers, $this->employees));
    }

    public function testEachRequestReachesTheRealmItIsUnderTheLongestFirst(): void
    {
        foreach (['https://idp.test/realms/employees', 'https://idp.test/realms/customers', 'https://idp.test'] as $issuer) {
            self::assertSame($issuer, $this->http->request('GET', $issuer.'/.well-known/openid-configuration')->toArray()['issuer']);
        }
        self::assertSame(404, $this->http->request('GET', 'https://elsewhere.test/.well-known/openid-configuration')->getStatusCode());
    }

    public function testAGrantHandlerKnowsWhichRealmWasAsked(): void
    {
        $handler = static fn (array $form, KeycloakStub $realm): MockResponse => new MockResponse((string) json_encode(['access_token' => $realm->issuer(), 'expires_in' => 300]));
        $this->customers->onGrant($handler);
        $this->employees->onGrant($handler);

        $tokens = (new KeycloakClient($this->http, 'https://idp.test/realms/employees', 'app'))->password('user', 'secret');

        self::assertSame('https://idp.test/realms/employees', $tokens->accessToken);
        self::assertSame('https://idp.test/realms/employees', KeycloakStub::$requests[0]['_issuer']);
    }
}
