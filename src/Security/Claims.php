<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Security;

use Symfony\Component\Security\Core\Exception\BadCredentialsException;

/**
 * The verified claims of a Keycloak access token, as the access-token handler hands them to the
 * user provider: the standard ones typed, the rest reachable by name.
 *
 * `sub` is the identifier the handler resolved (its `claim` option, `sub` by default). `client` is
 * the token's `azp`, the Keycloak client it was minted for, which Keycloak sets from the
 * authenticated client: a caller cannot claim to be another one. A token this service issued
 * itself before Keycloak carries none, hence nullable.
 */
final readonly class Claims
{
    /**
     * @param list<string>                $audience    `aud`, one entry per audience whether the token carried a string or a list
     * @param list<string>                $realmRoles  `realm_access.roles`
     * @param array<string, list<string>> $clientRoles `resource_access.<client>.roles`, keyed by client
     * @param array<string, mixed>        $all         every claim as received
     */
    private function __construct(
        public string $sub,
        public ?string $issuer,
        public ?string $client,
        public array $audience,
        public array $realmRoles,
        public array $clientRoles,
        public array $all,
    ) {
    }

    /**
     * @param array<string, mixed> $attributes
     */
    public static function fromAttributes(string $sub, array $attributes): self
    {
        $clientRoles = [];
        foreach ((array) ($attributes['resource_access'] ?? []) as $client => $access) {
            $clientRoles[(string) $client] = self::strings((array) ($access['roles'] ?? []));
        }

        return new self(
            $sub,
            self::scalarString($attributes['iss'] ?? null),
            self::scalarString($attributes['azp'] ?? null),
            self::strings((array) ($attributes['aud'] ?? [])),
            self::strings((array) ($attributes['realm_access']['roles'] ?? [])),
            $clientRoles,
            $attributes,
        );
    }

    public function has(string $claim): bool
    {
        return \array_key_exists($claim, $this->all);
    }

    public function get(string $claim): mixed
    {
        return $this->all[$claim] ?? null;
    }

    /**
     * A claim the principal cannot be built without; its absence means the token is not one this
     * service expects, which is a credentials problem, not a server error.
     */
    public function string(string $claim): string
    {
        return $this->stringOrNull($claim) ?? throw new BadCredentialsException(\sprintf('The token carries no "%s" claim.', $claim));
    }

    public function stringOrNull(string $claim): ?string
    {
        $value = $this->all[$claim] ?? null;

        return \is_scalar($value) && '' !== (string) $value ? (string) $value : null;
    }

    /**
     * @return list<string>
     */
    public function list(string $claim): array
    {
        return self::strings((array) ($this->all[$claim] ?? []));
    }

    private static function scalarString(mixed $value): ?string
    {
        return \is_scalar($value) && '' !== (string) $value ? (string) $value : null;
    }

    /**
     * @param array<mixed> $values
     *
     * @return list<string>
     */
    private static function strings(array $values): array
    {
        $strings = [];
        foreach ($values as $value) {
            if (\is_scalar($value)) {
                $strings[] = (string) $value;
            }
        }

        return $strings;
    }
}
