<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Session;

use Vinh0809it\KeycloakBundle\Client\TokenSet;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * A Keycloak session kept in cookies, for a backend-for-frontend: the browser holds the tokens, its
 * JavaScript cannot read them (HttpOnly), and they travel only over TLS (Secure). Nothing is
 * stored server-side, so the firewall stays stateless.
 *
 *   access   the access token, read by keycloak.token_extractor.cookie on every request.
 *   refresh  the refresh token, on a narrow path so only the refresh and logout routes see it.
 *
 * Keycloak answers `refresh_expires_in: 0` for a refresh token that lives as long as the SSO
 * session; such a cookie gets `$refreshSessionLifetime` seconds, or is a browser-session cookie
 * when that is null.
 */
final readonly class SessionCookies
{
    public function __construct(
        private CookieOptions $access,
        private ?CookieOptions $refresh = null,
        private ?int $refreshSessionLifetime = 1209600,
    ) {
    }

    public function set(Response $response, TokenSet $tokens): void
    {
        $response->headers->setCookie(self::cookie($this->access, $tokens->accessToken, time() + $tokens->expiresIn));

        if (null === $this->refresh || null === $tokens->refreshToken) {
            return;
        }
        $expires = match (true) {
            $tokens->refreshExpiresIn > 0 => time() + $tokens->refreshExpiresIn,
            null !== $this->refreshSessionLifetime => time() + $this->refreshSessionLifetime,
            default => 0,
        };
        $response->headers->setCookie(self::cookie($this->refresh, $tokens->refreshToken, $expires));
    }

    /**
     * Ends the session in the browser. The access cookie is cleared host-only as well as on its
     * domain, so one set before a domain was configured goes too.
     */
    public function clear(Response $response): void
    {
        self::expire($response, $this->access);
        if (null !== $this->access->domain) {
            self::expire($response, new CookieOptions($this->access->name, $this->access->path, null, $this->access->sameSite));
        }
        if (null !== $this->refresh) {
            self::expire($response, $this->refresh);
        }
    }

    public function refreshToken(Request $request): ?string
    {
        $token = null === $this->refresh ? null : $request->cookies->get($this->refresh->name);

        return \is_string($token) && '' !== $token ? $token : null;
    }

    private static function cookie(CookieOptions $options, string $value, int $expires): Cookie
    {
        return Cookie::create($options->name, $value, $expires, $options->path, $options->domain, true, true, false, $options->sameSite);
    }

    private static function expire(Response $response, CookieOptions $options): void
    {
        $response->headers->clearCookie($options->name, $options->path, $options->domain, true, true, $options->sameSite);
    }
}
