<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Security;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * The app's side of authentication: the verified claims of a token in, the app's principal out.
 *
 * Runs on every authenticated request of a stateless firewall, so the common path should be one
 * read. What a principal is — an entity row looked up or created by `sub`, a value object built
 * from the claims alone — is the app's decision; the bundle only routes the token to the resolver
 * registered for its client.
 */
interface ClaimsResolverInterface
{
    /**
     * @throws \Symfony\Component\Security\Core\Exception\AuthenticationException when the claims do not name a principal this app serves
     */
    public function resolve(Claims $claims): UserInterface;
}
