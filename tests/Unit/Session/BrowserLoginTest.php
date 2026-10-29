<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Tests\Unit\Session;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Vinh0809it\KeycloakBundle\Client\Exception\RequestRefusedException;
use Vinh0809it\KeycloakBundle\Client\KeycloakClient;
use Vinh0809it\KeycloakBundle\Session\BrowserLogin;
use Vinh0809it\KeycloakBundle\Session\CookieOptions;
use Vinh0809it\KeycloakBundle\Session\LoginFailedException;
use Vinh0809it\KeycloakBundle\Test\KeycloakStub;

final class BrowserLoginTest extends TestCase
{
    private const REALM = 'https://keycloak.test/realms/test';
    private const CALLBACK = 'https://app.test/callback';

    private int $now = 1_800_000_000;
    /** The code challenge of the last authorization URL, which the stub realm checks the verifier against. */
    private ?string $challenge = null;
    private BrowserLogin $login;

    protected function setUp(): void
    {
        KeycloakStub::reset();
        $realm = new KeycloakStub(self::REALM, sys_get_temp_dir().'/keycloak-bundle-test/login', new ArrayAdapter());
        // The realm's token endpoint: the code `c1`, redeemed by the verifier of the challenge it was issued for.
        $realm->onGrant(function (array $form): ?MockResponse {
            if ('authorization_code' !== ($form['grant_type'] ?? null)) {
                return null;
            }
            $verified = rtrim(strtr(base64_encode(hash('sha256', (string) $form['code_verifier'], true)), '+/', '-_'), '=') === $this->challenge;

            return 'c1' === $form['code'] && self::CALLBACK === $form['redirect_uri'] && $verified
                ? new MockResponse('{"access_token":"at","expires_in":300,"refresh_token":"rt"}')
                : new MockResponse('{"error":"invalid_grant"}', ['http_code' => 400]);
        });

        $this->login = new BrowserLogin(
            new KeycloakClient(new MockHttpClient($realm), self::REALM, 'web-app'),
            new CookieOptions('kc_login', '/'),
            'app-secret',
            ['https://web.example.com', 'https://*.apps.example.com'],
            fn (): int => $this->now,
        );
    }

    public function testStartRedirectsToTheRealmWithStateAndPkceKeptInALoginCookie(): void
    {
        $redirect = $this->login->start(self::CALLBACK, '/orders', ['login_hint' => 'user@example.com']);
        $query = $this->authorization($redirect);

        self::assertSame('web-app', $query['client_id']);
        self::assertSame(self::CALLBACK, $query['redirect_uri']);
        self::assertSame('S256', $query['code_challenge_method']);
        self::assertSame('user@example.com', $query['login_hint']);
        self::assertGreaterThanOrEqual(43, \strlen($query['state']));

        $cookie = $this->cookie($redirect);
        self::assertTrue($cookie->isHttpOnly() && $cookie->isSecure());
        self::assertSame('lax', $cookie->getSameSite());
        self::assertSame($this->now + BrowserLogin::LIFETIME, $cookie->getExpiresTime());
        self::assertStringNotContainsString($query['state'], (string) $cookie->getValue(), 'the cookie is encoded');
    }

    public function testTheCallbackOfThisBrowsersLoginExchangesTheCodeWithItsVerifier(): void
    {
        $redirect = $this->login->start(self::CALLBACK, '/orders');

        $done = $this->login->finish($this->callbackOf($redirect, ['code' => 'c1', 'iss' => self::REALM]));

        self::assertSame('at', $done->tokens->accessToken);
        self::assertSame('/orders', $done->returnTo);
    }

    public function testAStateThatIsNotTheLoginsOwnIsRefusedAndItsCodeSpent(): void
    {
        $redirect = $this->login->start(self::CALLBACK);

        try {
            $this->login->finish($this->callbackOf($redirect, ['code' => 'c1', 'state' => 'forged']));
            self::fail('A forged state was accepted.');
        } catch (LoginFailedException $e) {
            self::assertStringContainsString('state', $e->getMessage());
        }

        $exchanges = array_values(array_filter(KeycloakStub::$requests, static fn (array $request): bool => 'authorization_code' === ($request['grant_type'] ?? null)));
        self::assertCount(1, $exchanges, 'the code is redeemed once, so nobody else can');
        self::assertSame('c1', $exchanges[0]['code']);
        self::assertNotSame($this->challenge, rtrim(strtr(base64_encode(hash('sha256', (string) $exchanges[0]['code_verifier'], true)), '+/', '-_'), '='), 'with a verifier the login never had');
    }

    public function testACallbackWithNoLoginInProgressHasItsCodeSpentToo(): void
    {
        try {
            $this->login->finish(Request::create(self::CALLBACK, 'GET', ['state' => 's', 'code' => 'stolen']));
            self::fail('A callback without a login was accepted.');
        } catch (LoginFailedException) {
        }

        self::assertSame(['stolen'], array_column(array_filter(KeycloakStub::$requests, static fn (array $request): bool => 'authorization_code' === ($request['grant_type'] ?? null)), 'code'));
    }

    public function testAnotherIssuersCallbackIsRefused(): void
    {
        $this->expectException(LoginFailedException::class);

        $this->login->finish($this->callbackOf($this->login->start(self::CALLBACK), ['code' => 'c1', 'iss' => 'https://elsewhere.test']));
    }

    public function testALoginTheRealmEndedCarriesItsError(): void
    {
        try {
            $this->login->finish($this->callbackOf($this->login->start(self::CALLBACK, '/orders'), ['error' => 'access_denied', 'error_description' => 'The user said no']));
            self::fail('An ended login was completed.');
        } catch (LoginFailedException $e) {
            self::assertSame('access_denied', $e->error);
            self::assertSame('/orders', $e->returnTo);
            self::assertStringContainsString('The user said no', $e->getMessage());
        }
    }

    public function testNoLoginInProgressIsRefused(): void
    {
        $this->expectException(LoginFailedException::class);
        $this->expectExceptionMessage('no login in progress');

        $this->login->finish(Request::create(self::CALLBACK, 'GET', ['state' => 's', 'code' => 'c1']));
    }

    public function testATamperedLoginCookieIsRefused(): void
    {
        $redirect = $this->login->start(self::CALLBACK, '/orders');
        $request = $this->callbackOf($redirect, ['code' => 'c1']);
        [$payload, $signature] = explode('.', (string) $request->cookies->get('kc_login'));
        $login = json_decode((string) base64_decode(strtr($payload, '-_', '+/')), true);
        $login['return_to'] = 'https://evil.test';
        $request->cookies->set('kc_login', rtrim(strtr(base64_encode((string) json_encode($login)), '+/', '-_'), '=').'.'.$signature);

        $this->expectException(LoginFailedException::class);
        $this->login->finish($request);
    }

    public function testAnExpiredLoginIsRefused(): void
    {
        $request = $this->callbackOf($this->login->start(self::CALLBACK), ['code' => 'c1']);
        $this->now += BrowserLogin::LIFETIME + 1;

        $this->expectException(LoginFailedException::class);
        $this->expectExceptionMessage('expired');
        $this->login->finish($request);
    }

    public function testACodeTheRealmRefusesFailsTheLoginWithItsError(): void
    {
        try {
            $this->login->finish($this->callbackOf($this->login->start(self::CALLBACK, '/orders'), ['code' => 'spent']));
            self::fail('A refused code completed the login.');
        } catch (LoginFailedException $e) {
            self::assertSame('invalid_grant', $e->error);
            self::assertSame('/orders', $e->returnTo, 'the app can send the browser back with the error');
            self::assertInstanceOf(RequestRefusedException::class, $e->getPrevious());
        }
    }

    /** @return iterable<string, array{string, bool}> */
    public static function returnUrls(): iterable
    {
        yield 'a path of this app' => ['/orders?tab=2', true];
        yield 'an allowed origin' => ['https://web.example.com/orders', true];
        yield 'a subdomain of an allowed wildcard' => ['https://shop.apps.example.com/', true];
        yield 'another origin' => ['https://evil.test/', false];
        yield 'the wildcard\'s own domain' => ['https://apps.example.com/', false];
        yield 'another scheme' => ['http://web.example.com/', false];
        yield 'another port' => ['https://web.example.com:8443/', false];
        yield 'a protocol-relative URL' => ['//evil.test/', false];
        yield 'a backslash path' => ['/\\evil.test', false];
        yield 'credentials in the URL' => ['https://web.example.com@evil.test/', false];
        yield 'javascript' => ['javascript:alert(1)', false];
    }

    #[DataProvider('returnUrls')]
    public function testOnlyAPathOrAnAllowedOriginIsAPageToReturnTo(string $url, bool $allowed): void
    {
        if (!$allowed) {
            $this->expectException(LoginFailedException::class);
        }

        $done = $this->login->finish($this->callbackOf($this->login->start(self::CALLBACK, $url), ['code' => 'c1']));
        self::assertSame($url, $done->returnTo);
    }

    public function testClearLoginCookieExpiresIt(): void
    {
        $response = new Response();
        $this->login->clearLoginCookie($response);

        $cookie = $response->headers->getCookies()[0];
        self::assertSame('kc_login', $cookie->getName());
        self::assertTrue($cookie->isCleared());
    }

    /** @return array<string, string> */
    private function authorization(RedirectResponse $redirect): array
    {
        parse_str((string) parse_url($redirect->getTargetUrl(), \PHP_URL_QUERY), $query);
        $this->challenge = (string) $query['code_challenge'];

        /* @var array<string, string> $query */
        return $query;
    }

    private function cookie(RedirectResponse $redirect): Cookie
    {
        return $redirect->headers->getCookies()[0];
    }

    /**
     * The realm's redirect back: the login's own state unless $params says otherwise, with the
     * login cookie the browser kept.
     *
     * @param array<string, string> $params
     */
    private function callbackOf(RedirectResponse $redirect, array $params): Request
    {
        $query = $this->authorization($redirect);

        return Request::create(self::CALLBACK, 'GET', $params + ['state' => $query['state']], ['kc_login' => (string) $this->cookie($redirect)->getValue()]);
    }
}
