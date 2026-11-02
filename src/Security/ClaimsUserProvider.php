<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Security;

use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\AttributesBasedUserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * The firewall's user provider: the verified claims in, the principal out, through a resolver
 * picked by the token's client (`azp`), else a default. A token of an issuer with resolvers of its
 * own (a `by_realm` realm, an other issuer) is picked among those alone; any other token among the
 * firewall's.
 *
 * One realm can serve several kinds of principal (the same person may sign in as a customer and as
 * an employee), and the client the token was minted for is what tells them
 * apart; `aud` would not, since both clients may carry the same audience. A client with no
 * resolver and no default is refused: an unknown client is not a principal of this app.
 *
 * @implements AttributesBasedUserProviderInterface<UserInterface>
 */
final readonly class ClaimsUserProvider implements AttributesBasedUserProviderInterface
{
    /**
     * @param array<string, ClaimsResolverInterface>                                                                                                           $byClient Keycloak client id (`azp`) => resolver
     * @param list<array{provider: array{url: string, issuer: ?string}, resolver: ?ClaimsResolverInterface, byClient: array<string, ClaimsResolverInterface>}> $byIssuer the issuers with resolvers of their own
     */
    public function __construct(
        private ?ClaimsResolverInterface $default,
        private array $byClient = [],
        private array $byIssuer = [],
    ) {
    }

    /**
     * @param array<string, mixed> $attributes the verified claims
     */
    public function loadUserByIdentifier(string $identifier, array $attributes = []): UserInterface
    {
        $claims = Claims::fromAttributes($identifier, $attributes);
        $resolvers = $this->forIssuer($claims->issuer) ?? ['resolver' => $this->default, 'byClient' => $this->byClient];
        $resolver = (null !== $claims->client ? $resolvers['byClient'][$claims->client] ?? null : null)
            ?? $resolvers['resolver']
            ?? throw new UserNotFoundException(\sprintf('No principal for tokens of client "%s".', $claims->client ?? ''));

        return $resolver->resolve($claims);
    }

    /**
     * The resolvers of the issuer that signed the token, when it has its own.
     *
     * @return ?array{resolver: ?ClaimsResolverInterface, byClient: array<string, ClaimsResolverInterface>}
     */
    private function forIssuer(?string $issuer): ?array
    {
        if (null === $issuer) {
            return null;
        }
        foreach ($this->byIssuer as $entry) {
            if (\in_array($issuer, RealmTokenHandlerFactory::issuers([$entry['provider']]), true)) {
                return $entry;
            }
        }

        return null;
    }

    /** The firewall is stateless: the principal is rebuilt from the bearer on every request. */
    public function refreshUser(UserInterface $user): UserInterface
    {
        return $user;
    }

    public function supportsClass(string $class): bool
    {
        return true;
    }
}
