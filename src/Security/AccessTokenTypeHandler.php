<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Security;

use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

/**
 * Refuses a Keycloak realm's tokens that are not access tokens. Keycloak signs its ID tokens
 * (`typ: ID`) and logout tokens (`typ: Logout`) with the same keys as its access tokens
 * (`typ: Bearer`), and an ID token's `aud` is the client it was issued to, which may be this
 * firewall's audience. Tokens of the firewall's other issuers carry their own conventions and pass.
 *
 * @internal
 */
final readonly class AccessTokenTypeHandler implements AccessTokenHandlerInterface
{
    /**
     * @param list<string> $realmIssuers the `iss` of the firewall's Keycloak realms
     */
    public function __construct(
        private AccessTokenHandlerInterface $inner,
        private array $realmIssuers,
    ) {
    }

    public function getUserBadgeFrom(#[\SensitiveParameter] string $accessToken): UserBadge
    {
        $badge = $this->inner->getUserBadgeFrom($accessToken);
        $claims = $badge->getAttributes() ?? [];
        $type = $claims['typ'] ?? null;

        if (\in_array($claims['iss'] ?? null, $this->realmIssuers, true) && null !== $type && (!\is_string($type) || 0 !== strcasecmp($type, 'Bearer'))) {
            throw new BadCredentialsException(\sprintf('A "%s" token is not an access token.', \is_scalar($type) ? $type : get_debug_type($type)));
        }

        return $badge;
    }
}
