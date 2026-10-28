<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Tests\Unit\Session;

use Vinh0809it\KeycloakBundle\Client\TokenSet;
use Vinh0809it\KeycloakBundle\Session\CookieOptions;
use Vinh0809it\KeycloakBundle\Session\SessionCookies;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

final class SessionCookiesTest extends TestCase
{
    public function testSetsBothTokensHttpOnlyAndSecureWhereEachIsConfigured(): void
    {
        $response = new Response();
        self::cookies('example.test')->set($response, new TokenSet('at', 300, 'rt', 1800));

        $access = self::byName($response)['at_cookie'];
        self::assertSame('at', $access->getValue());
        self::assertSame(['/', 'example.test', Cookie::SAMESITE_LAX], [$access->getPath(), $access->getDomain(), $access->getSameSite()]);
        self::assertTrue($access->isHttpOnly() && $access->isSecure());
        self::assertEqualsWithDelta(time() + 300, $access->getExpiresTime(), 2);

        $refresh = self::byName($response)['rt_cookie'];
        self::assertSame(['/web', null, Cookie::SAMESITE_STRICT], [$refresh->getPath(), $refresh->getDomain(), $refresh->getSameSite()], 'the refresh token stays with this service');
        self::assertTrue($refresh->isHttpOnly() && $refresh->isSecure());
        self::assertEqualsWithDelta(time() + 1800, $refresh->getExpiresTime(), 2);
    }

    public function testAnEmptyDomainIsHostOnly(): void
    {
        $response = new Response();
        self::cookies('')->set($response, new TokenSet('at', 300));

        self::assertNull(self::byName($response)['at_cookie']->getDomain());
        self::assertArrayNotHasKey('rt_cookie', self::byName($response), 'no refresh token, no refresh cookie');
    }

    public function testARefreshTokenWithoutExpiryGetsTheSessionLifetimeOrABrowserSession(): void
    {
        $response = new Response();
        self::cookies(null, 1209600)->set($response, new TokenSet('at', 300, 'rt', 0));
        self::assertEqualsWithDelta(time() + 1209600, self::byName($response)['rt_cookie']->getExpiresTime(), 2);

        $response = new Response();
        self::cookies(null, null)->set($response, new TokenSet('at', 300, 'rt', 0));
        self::assertSame(0, self::byName($response)['rt_cookie']->getExpiresTime());
    }

    public function testClearingExpiresTheAccessCookieOnItsDomainAndHostOnlyAndTheRefreshCookie(): void
    {
        $response = new Response();
        self::cookies('example.test')->clear($response);

        $cleared = array_map(static fn (Cookie $c): array => [$c->getName(), $c->getPath(), $c->getDomain()], $response->headers->getCookies());
        self::assertEqualsCanonicalizing([['at_cookie', '/', 'example.test'], ['at_cookie', '/', null], ['rt_cookie', '/web', null]], $cleared);
        foreach ($response->headers->getCookies() as $cookie) {
            self::assertTrue($cookie->isCleared());
        }
    }

    public function testReadsTheRefreshToken(): void
    {
        self::assertSame('rt', self::cookies()->refreshToken(new Request(cookies: ['rt_cookie' => 'rt'])));
        self::assertNull(self::cookies()->refreshToken(new Request(cookies: ['rt_cookie' => ''])));
        self::assertNull((new SessionCookies(new CookieOptions('at_cookie')))->refreshToken(new Request(cookies: ['rt_cookie' => 'rt'])), 'no refresh cookie configured');
    }

    private static function cookies(?string $domain = null, ?int $sessionLifetime = 1209600): SessionCookies
    {
        return new SessionCookies(
            new CookieOptions('at_cookie', '/', $domain, Cookie::SAMESITE_LAX),
            new CookieOptions('rt_cookie', '/web', null, Cookie::SAMESITE_STRICT),
            $sessionLifetime,
        );
    }

    /**
     * @return array<string, Cookie>
     */
    private static function byName(Response $response): array
    {
        $cookies = [];
        foreach ($response->headers->getCookies() as $cookie) {
            $cookies[$cookie->getName()] = $cookie;
        }

        return $cookies;
    }
}
