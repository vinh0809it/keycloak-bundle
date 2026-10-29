<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Client;

/**
 * What the token endpoint answered for a grant.
 *
 * `refreshExpiresIn` is 0 when the refresh token only dies with the Keycloak session (an offline
 * token, or a realm without an idle timeout); a client-credentials grant carries no refresh token.
 */
final readonly class TokenSet
{
    public function __construct(
        public string $accessToken,
        public int $expiresIn,
        public ?string $refreshToken = null,
        public int $refreshExpiresIn = 0,
        public ?string $idToken = null,
        public ?string $scope = null,
        public ?string $tokenType = null,
    ) {
    }

    /**
     * @param array<string, mixed> $response the token endpoint's JSON body
     */
    public static function fromResponse(array $response): self
    {
        return new self(
            (string) $response['access_token'],
            (int) ($response['expires_in'] ?? 0),
            self::stringOrNull($response['refresh_token'] ?? null),
            (int) ($response['refresh_expires_in'] ?? 0),
            self::stringOrNull($response['id_token'] ?? null),
            self::stringOrNull($response['scope'] ?? null),
            self::stringOrNull($response['token_type'] ?? null),
        );
    }

    private static function stringOrNull(mixed $value): ?string
    {
        return \is_string($value) && '' !== $value ? $value : null;
    }
}
