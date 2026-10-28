<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Session;

/**
 * Where one session cookie lives. An empty domain (an unset env var) means host-only.
 */
final readonly class CookieOptions
{
    public ?string $domain;

    public function __construct(
        public string $name,
        public string $path = '/',
        ?string $domain = null,
        public string $sameSite = 'lax',
    ) {
        $this->domain = '' === (string) $domain ? null : $domain;
    }
}
