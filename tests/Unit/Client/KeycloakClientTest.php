<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Tests\Unit\Client;

use Vinh0809it\KeycloakBundle\Client\Exception\InvalidClientException;
use Vinh0809it\KeycloakBundle\Client\Exception\KeycloakUnavailableException;
use Vinh0809it\KeycloakBundle\Client\Exception\RequestRefusedException;
use Vinh0809it\KeycloakBundle\Client\KeycloakClient;
use Vinh0809it\KeycloakBundle\Client\ServiceToken;
use Vinh0809it\KeycloakBundle\Test\KeycloakStub;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpClient\Exception\TransportException;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

final class KeycloakClientTest extends TestCase
{
    private const REALM = 'https://keycloak.test/realms/test';

    private KeycloakStub $stub;

    protected function setUp(): void
    {
        KeycloakStub::reset();
        $this->stub = new KeycloakStub(self::REALM, sys_get_temp_dir().'/keycloak-bundle-test/client', new ArrayAdapter());
        $this->stub->serviceClient('test-api', ['sub' => 'svc', 'azp' => 'test-api']);
    }

    public function testAConfidentialClientAuthenticatesItsGrants(): void
    {
        $tokens = $this->client('test-api', 'secret')->clientCredentials();

        self::assertNotSame('', $tokens->accessToken);
        self::assertSame(300, $tokens->expiresIn);
        self::assertNull($tokens->refreshToken);
        self::assertSame(
            ['grant_type' => 'client_credentials', 'client_id' => 'test-api', 'client_secret' => 'secret', '_path' => '/realms/test/protocol/openid-connect/token', '_issuer' => self::REALM],
            KeycloakStub::$requests[0],
            'a realm URL with or without its trailing slash reaches the same endpoint',
        );
    }

    public function testAPublicClientSendsItsIdAlone(): void
    {
        $this->stub->on('POST', '/protocol/openid-connect/logout', static fn (): MockResponse => new MockResponse('', ['http_code' => 204]));

        $this->client('mobile-app', null)->logout('refresh-1');

        self::assertSame(['refresh_token' => 'refresh-1', 'client_id' => 'mobile-app', '_path' => '/realms/test/protocol/openid-connect/logout', '_issuer' => self::REALM], KeycloakStub::$requests[0]);
    }

    public function testAnSpiDirectGrantCarriesItsOwnFields(): void
    {
        $client = new KeycloakClient(new MockHttpClient(static function (string $method, string $url, array $options): MockResponse {
            parse_str((string) $options['body'], $form);
            self::assertSame(['grant_type' => 'password', 'username' => 'user@example.com', 'password' => '', 'session' => 's1', 'otp' => '123456', 'client_id' => 'mobile-app'], $form);

            return new MockResponse((string) json_encode(['access_token' => 'at', 'expires_in' => 60, 'refresh_token' => 'rt', 'refresh_expires_in' => 0]));
        }), self::REALM, 'mobile-app');

        $tokens = $client->password('user@example.com', '', ['session' => 's1', 'otp' => '123456']);

        self::assertSame('rt', $tokens->refreshToken);
        self::assertSame(0, $tokens->refreshExpiresIn);
    }

    public function testARefusedGrantIsTheCallersAndARefusedClientIsOurs(): void
    {
        try {
            $this->answering(400, ['error' => 'invalid_grant', 'error_description' => 'Code not valid'])->refresh('spent');
            self::fail('a refused grant throws');
        } catch (RequestRefusedException $e) {
            self::assertNotInstanceOf(InvalidClientException::class, $e);
            self::assertSame('invalid_grant', $e->error);
            self::assertSame(400, $e->status);
        }

        $this->expectException(InvalidClientException::class);
        $this->client('test-api', '')->clientCredentials();
    }

    public function testKeycloakDownIsUnavailable(): void
    {
        $this->expectException(KeycloakUnavailableException::class);

        $this->answering(503, [])->clientCredentials();
    }

    public function testAnUnreachableKeycloakIsUnavailable(): void
    {
        $client = new KeycloakClient(new MockHttpClient(static fn (): never => throw new TransportException('connection refused')), self::REALM, 'test-api', 'secret');

        $this->expectException(KeycloakUnavailableException::class);

        $client->clientCredentials();
    }

    public function testASuccessWithoutAnAccessTokenIsUnavailable(): void
    {
        $this->expectException(KeycloakUnavailableException::class);

        $this->answering(200, ['token_type' => 'Bearer'])->clientCredentials();
    }

    public function testTheAuthorizationUrlIsTheBrowsersRealmWithPkce(): void
    {
        $client = new KeycloakClient(new MockHttpClient(), 'http://keycloak:8080/realms/test/', 'web-app', 'secret', self::REALM);

        self::assertSame(
            self::REALM.'/protocol/openid-connect/auth?client_id=web-app&response_type=code&scope=openid&redirect_uri=https%3A%2F%2Fapp.test%2Fcallback&state=st&code_challenge=ch&code_challenge_method=S256&login_hint=user%40example.com',
            $client->authorizationUrl('https://app.test/callback', 'st', 'ch', ['login_hint' => 'user@example.com', 'prompt' => null]),
        );
    }

    public function testTheAuthorizationUrlTakesItsScopeButKeepsItsOwnStateAndPkce(): void
    {
        $client = new KeycloakClient(new MockHttpClient(), self::REALM, 'web-app');

        self::assertSame(
            self::REALM.'/protocol/openid-connect/auth?client_id=web-app&response_type=code&scope=openid%20offline_access&redirect_uri=https%3A%2F%2Fapp.test%2Fcallback&state=st&code_challenge=ch&code_challenge_method=S256',
            $client->authorizationUrl('https://app.test/callback', 'st', 'ch', ['scope' => 'openid offline_access', 'state' => 'forged', 'code_challenge_method' => null, 'redirect_uri' => 'https://evil.test', 'response_mode' => 'fragment']),
        );
    }

    public function testATokenSetKeepsItsScopeAndType(): void
    {
        $tokens = $this->answering(200, ['access_token' => 'at', 'expires_in' => 300, 'scope' => 'openid email', 'token_type' => 'Bearer'])->clientCredentials();

        self::assertSame('openid email', $tokens->scope);
        self::assertSame('Bearer', $tokens->tokenType);
    }

    public function testUserinfoIsAskedWithTheUsersOwnToken(): void
    {
        $this->stub->on('GET', '/protocol/openid-connect/userinfo', static fn (array $form, array $options): MockResponse => new MockResponse((string) json_encode([
            'sub' => 'u1',
            'authorization' => $options['normalized_headers']['authorization'][0] ?? null,
        ])));

        self::assertSame(['sub' => 'u1', 'authorization' => 'Authorization: Bearer user-token'], $this->client('mobile-app', null)->userinfo('user-token'));
        self::assertSame('/realms/test/protocol/openid-connect/userinfo', KeycloakStub::$requests[0]['_path']);
    }

    public function testTheLogoutUrlEndsTheBrowsersSessionAtThePublicRealm(): void
    {
        $client = new KeycloakClient(new MockHttpClient(), 'http://keycloak:8080/realms/test/', 'web-app', 'secret', self::REALM);

        self::assertSame(
            self::REALM.'/protocol/openid-connect/logout?client_id=web-app&post_logout_redirect_uri=https%3A%2F%2Fapp.test%2Fbye&id_token_hint=id.token.value',
            $client->logoutUrl('https://app.test/bye', 'id.token.value'),
        );
        self::assertSame(
            self::REALM.'/protocol/openid-connect/logout?client_id=web-app&post_logout_redirect_uri=https%3A%2F%2Fapp.test%2Fbye&state=s1',
            $client->logoutUrl('https://app.test/bye', state: 's1'),
            'without an ID token Keycloak asks the user to confirm',
        );
    }

    public function testARealmResourceIsReachedUnderTheRealm(): void
    {
        $this->stub->on('POST', '/my-provider/send', static fn (array $form, array $options): MockResponse => new MockResponse((string) json_encode(['session' => 's1', 'sent' => json_decode((string) $options['body'], true)])));

        $body = $this->client('mobile-app', null)->realm('POST', 'my-provider/send', ['json' => ['to' => 'user@example.com']]);

        self::assertSame(['session' => 's1', 'sent' => ['to' => 'user@example.com']], $body);
    }

    public function testARefusedRealmResourceKeepsItsBody(): void
    {
        $this->stub->on('POST', '/my-provider/send', static fn (): MockResponse => new MockResponse((string) json_encode(['code' => 'throttled']), ['http_code' => 429]));

        try {
            $this->client('mobile-app', null)->realm('POST', 'my-provider/send', ['json' => []]);
            self::fail('a 4xx throws');
        } catch (RequestRefusedException $e) {
            self::assertSame(429, $e->status);
            self::assertSame(['code' => 'throttled'], $e->body);
        }
    }

    public function testAServiceTokenIsReusedUntilItNearlyExpires(): void
    {
        $now = 1_000;
        $token = new ServiceToken($this->client('test-api', 'secret'), static function () use (&$now): int {
            return $now;
        });

        $first = $token->get();
        $now += 260;
        self::assertSame($first, $token->get(), 'still 40s left: reused');
        self::assertCount(1, KeycloakStub::$requests);

        $now += 20;
        $token->get();
        self::assertCount(2, KeycloakStub::$requests, 'within the 30s margin: minted again');
    }

    public function testAServiceTokenSharedThroughACacheIsMintedOnceAcrossInstances(): void
    {
        $now = 1_000;
        $clock = static function () use (&$now): int {
            return $now;
        };
        $cache = new ArrayAdapter();

        $first = (new ServiceToken($this->client('test-api', 'secret'), $clock, $cache, 'svc'))->get();
        $second = (new ServiceToken($this->client('test-api', 'secret'), $clock, $cache, 'svc'))->get();

        self::assertSame($first, $second, 'a second request reuses the token the first minted');
        self::assertCount(1, KeycloakStub::$requests);

        $now += 280;
        (new ServiceToken($this->client('test-api', 'secret'), $clock, $cache, 'svc'))->get();
        self::assertCount(2, KeycloakStub::$requests, 'a cached token within the margin is minted again');
    }

    private function client(string $id, ?string $secret): KeycloakClient
    {
        return new KeycloakClient(new MockHttpClient($this->stub), self::REALM.'/', $id, $secret);
    }

    /**
     * @param array<string, mixed> $body
     */
    private function answering(int $status, array $body): KeycloakClient
    {
        return new KeycloakClient(new MockHttpClient(new MockResponse((string) json_encode($body), ['http_code' => $status])), self::REALM, 'test-api', 'secret');
    }
}
