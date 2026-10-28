<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Security;

/**
 * The `iss` a bearer claims, read without checking its signature: only to decide which verifier a
 * token belongs to. Whatever verifier that is checks the signature and the issuer again.
 */
final class UnverifiedIssuer
{
    /** The claimed `iss` without a trailing slash, or null when $token is not a JWT carrying one. */
    public static function of(string $token): ?string
    {
        $payload = explode('.', $token)[1] ?? '';
        $claims = json_decode((string) base64_decode(strtr($payload, '-_', '+/'), true), true);

        return \is_array($claims) && \is_string($claims['iss'] ?? null) ? rtrim($claims['iss'], '/') : null;
    }
}
