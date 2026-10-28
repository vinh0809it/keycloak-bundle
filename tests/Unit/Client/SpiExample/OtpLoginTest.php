<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Tests\Unit\Client\SpiExample;

use Vinh0809it\KeycloakBundle\Client\Exception\RequestRefusedException;
use Vinh0809it\KeycloakBundle\Client\KeycloakClient;
use Vinh0809it\KeycloakBundle\Test\KeycloakStub;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * An SPI tested against the stub realm: its endpoint and its grant registered from outside, with
 * nothing of the SPI inside the bundle.
 */
final class OtpLoginTest extends TestCase
{
    private const string REALM = 'https://keycloak.test/realms/test';

    private KeycloakStub $realm;
    private OtpLogin $otp;

    protected function setUp(): void
    {
        KeycloakStub::reset();
        $this->realm = new KeycloakStub(self::REALM, sys_get_temp_dir().'/keycloak-bundle-test/spi', new ArrayAdapter());
        $this->realm->on('POST', '/otp/send', static fn (): MockResponse => new MockResponse('{"session":"s1"}'));
        $this->realm->onGrant(fn (array $form): ?MockResponse => isset($form['otp'])
            ? ('123456' === $form['otp'] && 's1' === $form['session']
                ? new MockResponse((string) json_encode(['access_token' => $this->realm->sign(['sub' => 'u1', 'azp' => 'app']), 'expires_in' => 300]))
                : new MockResponse('{"error":"invalid_grant"}', ['http_code' => 400]))
            : null);

        $this->otp = new OtpLogin(new KeycloakClient(new MockHttpClient($this->realm), self::REALM, 'app'));
    }

    public function testTheRightCodeSignsIn(): void
    {
        $session = $this->otp->send('user@example.com');

        self::assertNotSame('', $this->otp->login('user@example.com', $session, '123456')->accessToken);
        self::assertSame(['grant_type' => 'password', 'username' => 'user@example.com', 'password' => '', 'session' => 's1', 'otp' => '123456', 'client_id' => 'app', '_path' => '/realms/test/protocol/openid-connect/token'], KeycloakStub::$requests[1]);
    }

    public function testAWrongCodeIsTheUsersToRetry(): void
    {
        $this->expectException(RequestRefusedException::class);

        $this->otp->login('user@example.com', $this->otp->send('user@example.com'), '000000');
    }

    public function testAGrantNoHandlerRecognisesIsRefusedAsAnUnknownClient(): void
    {
        $this->expectException(RequestRefusedException::class);
        $this->expectExceptionMessage('unauthorized_client');

        (new KeycloakClient(new MockHttpClient($this->realm), self::REALM, 'app'))->password('user@example.com', 'secret');
    }
}
