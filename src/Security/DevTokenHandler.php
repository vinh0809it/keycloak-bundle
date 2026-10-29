<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Security;

use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

/**
 * Configured bearers for local development and tests, in front of the real verifier.
 *
 * A configured token (`member.1`, `staff.2`...), or one matching a configured pattern
 * (`{azp}~{sub}` takes `mobile-app~42`), answers with its configured claims, in the same
 * attribute shape the `oidc` handler produces for a Keycloak token, so the user provider resolves
 * it through the very same branch as a real one. Anything else goes to the decorated handler, so
 * a signed token keeps working beside the fake ones. The bundle refuses to register this in prod.
 */
final readonly class DevTokenHandler implements AccessTokenHandlerInterface
{
    /**
     * @param array<string, array<string, mixed>> $tokens bearer => claims; `sub` defaults to the bearer. A bearer with `{name}`
     *                                                    placeholders matches any text in their place and sets claim `name` to it
     */
    public function __construct(
        private AccessTokenHandlerInterface $inner,
        private array $tokens,
    ) {
    }

    public function getUserBadgeFrom(#[\SensitiveParameter] string $accessToken): UserBadge
    {
        $claims = $this->tokens[$accessToken] ?? $this->matchPattern($accessToken);
        if (null === $claims) {
            return $this->inner->getUserBadgeFrom($accessToken);
        }

        $claims += ['sub' => $accessToken];

        return new UserBadge((string) $claims['sub'], null, $claims);
    }

    public static function isPattern(string $token): bool
    {
        return [] !== self::placeholders($token);
    }

    /** @return list<string> the names of the `{name}` placeholders in $token, in order */
    public static function placeholders(string $token): array
    {
        preg_match_all('/\{(\w+)\}/', $token, $matches);

        return $matches[1];
    }

    /** Whether the pattern's literal text holds a character no compact JWT does, so it never takes one. */
    public static function isSafePattern(string $token): bool
    {
        return 1 === preg_match('/[^A-Za-z0-9_.\-]/', (string) preg_replace('/\{\w+\}/', '', $token));
    }

    /** @return array<string, mixed>|null the claims of the first pattern $token matches, its placeholders' text included */
    private function matchPattern(string $token): ?array
    {
        foreach ($this->tokens as $pattern => $claims) {
            $pattern = (string) $pattern;
            if (!self::isPattern($pattern)) {
                continue;
            }
            $parts = preg_split('/\{(\w+)\}/', $pattern, -1, \PREG_SPLIT_DELIM_CAPTURE) ?: [];
            $regex = '';
            foreach ($parts as $i => $part) {
                $regex .= 0 === $i % 2 ? preg_quote($part, '/') : '(?P<'.$part.'>.+?)';
            }
            if (1 === preg_match('/^'.$regex.'$/', $token, $match)) {
                return array_filter($match, 'is_string', \ARRAY_FILTER_USE_KEY) + $claims;
            }
        }

        return null;
    }
}
