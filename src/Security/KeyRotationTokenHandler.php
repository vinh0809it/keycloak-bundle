<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Security;

use Psr\Log\LoggerInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;
use Symfony\Component\Security\Http\AccessToken\Oidc\Exception\InvalidSignatureException;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

/**
 * Symfony's `oidc` handler in front of a key rotation: a token whose signature none of the cached
 * keys verifies drops the cached discovery and is verified once more against keys fetched afresh,
 * so a token signed by a key the realm published since is accepted without waiting for the cache
 * to expire. At most one refetch per {@see INTERVAL} seconds per firewall, shared through the
 * cache, so tokens with bad signatures cannot make every request fetch the realm's keys.
 */
final readonly class KeyRotationTokenHandler implements AccessTokenHandlerInterface
{
    public const INTERVAL = 60;

    /**
     * @param list<string> $cacheKeys the discovery cache entries holding the firewall's providers' keys
     */
    public function __construct(
        private AccessTokenHandlerInterface $inner,
        private CacheInterface $cache,
        private array $cacheKeys,
        private string $throttleKey,
        private ?LoggerInterface $logger = null,
    ) {
    }

    public function getUserBadgeFrom(#[\SensitiveParameter] string $accessToken): UserBadge
    {
        try {
            return $this->inner->getUserBadgeFrom($accessToken);
        } catch (BadCredentialsException $e) {
            if (!$e->getPrevious() instanceof InvalidSignatureException || !$this->mayRefetch()) {
                throw $e;
            }
        }

        $this->logger?->info('No cached key verifies the token\'s signature: refetching the providers\' keys.');
        foreach ($this->cacheKeys as $key) {
            $this->cache->delete($key);
        }

        return $this->inner->getUserBadgeFrom($accessToken);
    }

    private function mayRefetch(): bool
    {
        $first = false;
        $this->cache->get($this->throttleKey, static function (ItemInterface $item) use (&$first): int {
            $item->expiresAfter(self::INTERVAL);
            $first = true;

            return time();
        });

        return $first;
    }
}
