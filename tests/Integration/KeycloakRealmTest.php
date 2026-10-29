<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Tests\Integration;

use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpFoundation\Request;
use Vinh0809it\KeycloakBundle\Client\Exception\InvalidClientException;
use Vinh0809it\KeycloakBundle\Client\Exception\RequestRefusedException;
use Vinh0809it\KeycloakBundle\Client\KeycloakClient;
use Vinh0809it\KeycloakBundle\Client\ServiceToken;
use Vinh0809it\KeycloakBundle\Session\BrowserLogin;
use Vinh0809it\KeycloakBundle\Session\CookieOptions;
use Vinh0809it\KeycloakBundle\Session\LoginFailedException;
use Vinh0809it\KeycloakBundle\Tests\Integration\App\IntegrationKernel;

/**
 * The bundle against a real Keycloak running tests/Integration/realm.json, reached at KEYCLOAK_URL;
 * skipped without it. The realm URL is also the issuer, so it must be the one Keycloak's tokens name.
 */
final class KeycloakRealmTest extends WebTestCase
{
    private KernelBrowser $browser;

    protected static function getKernelClass(): string
    {
        return IntegrationKernel::class;
    }

    protected function setUp(): void
    {
        if ('' === (string) getenv('KEYCLOAK_URL')) {
            self::markTestSkipped('KEYCLOAK_URL is not set.');
        }

        $this->browser = self::createClient();
    }

    public function testAUsersTokenPassesTheFirewall(): void
    {
        $tokens = $this->app()->password('alice', 'alice-password');

        self::assertSame(200, $this->whoami($tokens->accessToken));
        self::assertMatchesRegularExpression('/^\{"user":"user:[0-9a-f-]{36}"\}$/', (string) $this->browser->getResponse()->getContent());
    }

    public function testAServiceAccountsTokenIsResolvedByItsClient(): void
    {
        $token = new ServiceToken($this->client('demo-service', 'demo-secret'));

        self::assertSame(200, $this->whoami($token->get()));
        self::assertStringStartsWith('{"user":"service:', (string) $this->browser->getResponse()->getContent());
        self::assertSame($token->get(), $token->get(), 'the token is reused while it is fresh');
    }

    public function testATokenMintedForAnotherAudienceIsRefused(): void
    {
        $tokens = $this->client('other-app')->password('alice', 'alice-password');

        self::assertSame(401, $this->whoami($tokens->accessToken));
    }

    public function testATamperedTokenIsRefused(): void
    {
        [$header, $payload, $signature] = explode('.', $this->app()->password('alice', 'alice-password')->accessToken);
        $claims = json_decode((string) base64_decode(strtr($payload, '-_', '+/'), true), true);
        \assert(\is_array($claims));
        $claims['sub'] = 'someone-else';
        $forged = rtrim(strtr(base64_encode((string) json_encode($claims)), '+/', '-_'), '=');

        self::assertSame(401, $this->whoami($header.'.'.$forged.'.'.$signature));
    }

    public function testARefreshedTokenAndUserinfo(): void
    {
        $tokens = $this->app()->password('alice', 'alice-password', ['scope' => 'openid']);
        \assert(null !== $tokens->refreshToken);

        self::assertContains('openid', explode(' ', (string) $tokens->scope));
        self::assertSame('Bearer', $tokens->tokenType);

        $refreshed = $this->app()->refresh($tokens->refreshToken);

        self::assertNotSame($tokens->accessToken, $refreshed->accessToken);
        self::assertSame(200, $this->whoami($refreshed->accessToken));
        self::assertSame('alice', $this->app()->userinfo($refreshed->accessToken)['preferred_username'] ?? null);
    }

    public function testARevokedRefreshTokenNoLongerRefreshes(): void
    {
        $refreshToken = $this->app()->password('alice', 'alice-password')->refreshToken;
        \assert(null !== $refreshToken);

        $this->app()->revoke($refreshToken);

        $this->expectException(RequestRefusedException::class);
        $this->app()->refresh($refreshToken);
    }

    public function testLogoutEndsTheSession(): void
    {
        $refreshToken = $this->app()->password('alice', 'alice-password')->refreshToken;
        \assert(null !== $refreshToken);

        $this->app()->logout($refreshToken);

        $this->expectException(RequestRefusedException::class);
        $this->app()->refresh($refreshToken);
    }

    public function testAWrongPasswordIsTheUsersToRetry(): void
    {
        try {
            $this->app()->password('alice', 'wrong');
            self::fail('The grant was accepted.');
        } catch (RequestRefusedException $e) {
            self::assertNotInstanceOf(InvalidClientException::class, $e);
            self::assertSame('invalid_grant', $e->error);
        }
    }

    public function testAWrongSecretIsTheClientsFault(): void
    {
        $this->expectException(InvalidClientException::class);

        $this->client('demo-service', 'wrong')->clientCredentials();
    }

    public function testTheBrowserUrlsAreAcceptedByTheRealm(): void
    {
        $http = HttpClient::create(['max_redirects' => 0]);

        $login = $http->request('GET', $this->app()->authorizationUrl('http://localhost/callback', 'state-1', rtrim(strtr(base64_encode(hash('sha256', 'verifier', true)), '+/', '-_'), '='), ['scope' => 'openid offline_access']));
        self::assertSame(200, $login->getStatusCode());
        self::assertStringContainsString('<form', $login->getContent());

        $logout = $http->request('GET', $this->app()->logoutUrl('http://localhost/bye', state: 'state-2'));
        self::assertSame(302, $logout->getStatusCode(), 'with no session to end, Keycloak goes straight back');
        self::assertSame('http://localhost/bye?state=state-2', $logout->getHeaders(false)['location'][0] ?? null);
    }

    public function testABrowserSignsInThroughTheRealmsLoginPage(): void
    {
        $login = new BrowserLogin($this->app(), new CookieOptions('kc_login'), 'app-secret');
        $start = $login->start('http://localhost/callback', '/orders');

        $request = Request::create(self::signIn($start->getTargetUrl()), 'GET', [], ['kc_login' => (string) $start->headers->getCookies()[0]->getValue()]);
        $done = $login->finish($request);

        self::assertSame('/orders', $done->returnTo);
        self::assertSame(200, $this->whoami($done->tokens->accessToken));
    }

    public function testTheCodeOfACallbackTheLoginRefusesCannotBeRedeemedAfterwards(): void
    {
        $login = new BrowserLogin($this->app(), new CookieOptions('kc_login'), 'app-secret');
        $verifier = str_repeat('v', 50);
        $callback = self::signIn($this->app()->authorizationUrl('http://localhost/callback', 'theirs', rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=')));
        parse_str((string) parse_url($callback, \PHP_URL_QUERY), $query);

        try {
            $login->finish(Request::create($callback));
            self::fail('A callback without a login was accepted.');
        } catch (LoginFailedException) {
        }

        $this->expectException(RequestRefusedException::class);
        $this->app()->exchangeCode((string) $query['code'], 'http://localhost/callback', $verifier);
    }

    /** A browser signing in as alice at $authorizationUrl: the URL of the realm's redirect back. */
    private static function signIn(string $authorizationUrl): string
    {
        $http = HttpClient::create(['max_redirects' => 0]);
        $page = $http->request('GET', $authorizationUrl);
        $cookies = implode('; ', array_map(static fn (string $header): string => explode(';', $header, 2)[0], $page->getHeaders()['set-cookie'] ?? []));
        self::assertSame(1, preg_match('/<form[^>]+action="([^"]+)"/', $page->getContent(), $form));
        $posted = $http->request('POST', html_entity_decode($form[1]), [
            'headers' => ['Cookie' => $cookies],
            'body' => ['username' => 'alice', 'password' => 'alice-password'],
        ]);
        self::assertSame(302, $posted->getStatusCode());
        $callback = $posted->getHeaders(false)['location'][0];
        self::assertStringStartsWith('http://localhost/callback?', $callback);

        return $callback;
    }

    private function app(): KeycloakClient
    {
        return $this->client('demo-app');
    }

    private function client(string $id, ?string $secret = null): KeycloakClient
    {
        return new KeycloakClient(HttpClient::create(), IntegrationKernel::realm(), $id, $secret);
    }

    private function whoami(string $accessToken): int
    {
        $this->browser->request('GET', '/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$accessToken]);

        return $this->browser->getResponse()->getStatusCode();
    }
}
