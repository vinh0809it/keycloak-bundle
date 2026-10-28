<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\AccessToken\AccessTokenExtractorInterface;

/**
 * An access token from a cookie, for a web build whose backend-for-frontend keeps the token in an
 * HttpOnly cookie. Only WHERE the token is read from: the firewall's token handler still decides
 * whether it is any good. List it after `header`, so a request carrying both is judged by its
 * bearer.
 */
final readonly class CookieTokenExtractor implements AccessTokenExtractorInterface
{
    public function __construct(private string $cookie)
    {
    }

    public function extractAccessToken(Request $request): ?string
    {
        $token = $request->cookies->get($this->cookie);

        return \is_string($token) && '' !== $token ? $token : null;
    }
}
