<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Tests\Functional\App;

use Vinh0809it\KeycloakBundle\Security\Claims;
use Vinh0809it\KeycloakBundle\Security\ClaimsResolverInterface;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\UserInterface;

/** A principal named after the resolver that built it and the token's `sub`. */
final readonly class PrefixResolver implements ClaimsResolverInterface
{
    public function __construct(private string $prefix)
    {
    }

    public function resolve(Claims $claims): UserInterface
    {
        return new InMemoryUser($this->prefix.':'.$claims->sub, null);
    }
}
