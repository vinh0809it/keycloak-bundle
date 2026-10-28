<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Tests\Functional\App;

use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

/**
 * A token the app issues itself, plugged in as a decorator of the firewall's keycloak token
 * handler: it answers its own (the literal `own-token` here, an `iss` of the app's in practice)
 * and hands every other bearer on.
 */
final readonly class OwnTokenHandler implements AccessTokenHandlerInterface
{
    public function __construct(private AccessTokenHandlerInterface $keycloak)
    {
    }

    public function getUserBadgeFrom(#[\SensitiveParameter] string $accessToken): UserBadge
    {
        if ('own-token' !== $accessToken) {
            return $this->keycloak->getUserBadgeFrom($accessToken);
        }

        return new UserBadge('own', static fn (string $id): InMemoryUser => new InMemoryUser('own:'.$id, null));
    }
}
