<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Security;

use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

/**
 * Literal bearers for local development and tests, in front of the real verifier.
 *
 * A configured token (`member.1`, `staff.2`...) answers with its configured claims, in the same
 * attribute shape the `oidc` handler produces for a Keycloak token, so the user provider resolves
 * it through the very same branch as a real one. Anything else goes to the decorated handler, so
 * a signed token keeps working beside the fake ones. The bundle refuses to register this in prod.
 */
final readonly class DevTokenHandler implements AccessTokenHandlerInterface
{
    /**
     * @param array<string, array<string, mixed>> $tokens literal bearer => claims; `sub` defaults to the bearer
     */
    public function __construct(
        private AccessTokenHandlerInterface $inner,
        private array $tokens,
    ) {
    }

    public function getUserBadgeFrom(#[\SensitiveParameter] string $accessToken): UserBadge
    {
        $claims = $this->tokens[$accessToken] ?? null;
        if (null === $claims) {
            return $this->inner->getUserBadgeFrom($accessToken);
        }

        $claims += ['sub' => $accessToken];

        return new UserBadge((string) $claims['sub'], null, $claims);
    }
}
