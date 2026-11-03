<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Security;

use Psr\Log\LoggerInterface;
use Vinh0809it\KeycloakBundle\Client\Exception\KeycloakUnavailableException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;
use Symfony\Component\Security\Http\AccessToken\Oidc\Exception\InvalidSignatureException;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpClientException;

/**
 * Symfony's `oidc` handler in front of a key rotation: a token whose signature none of the cached
 * keys verifies drops the cached discovery and is verified once more against keys fetched afresh,
 * so a token signed by a key the realm published since is accepted without waiting for the cache
 * to expire. At most one refetch per {@see INTERVAL} seconds per firewall, shared through the
 * cache, so tokens with bad signatures cannot make every request fetch the realm's keys.
 *
 * A realm that cannot be reached is a {@see KeycloakUnavailableException}, a server error, rather
 * than the 401 Symfony's handler answers, which a client takes for a sign-out. A refetch that
 * cannot reach the realm puts the keys it dropped back for {@see RESTORED_TTL} seconds, so a token
 * with a bad signature during an outage does not leave every request without keys.
 *
 * @internal
 */
final readonly class KeyRotationTokenHandler implements AccessTokenHandlerInterface
{
    public const INTERVAL = 60;
    public const RESTORED_TTL = 300;

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
            self::assertReachable($e);
            if (!$e->getPrevious() instanceof InvalidSignatureException || !$this->mayRefetch()) {
                throw $e;
            }
        }

        $this->logger?->info('No cached key verifies the token\'s signature: refetching the providers\' keys.');
        $dropped = [];
        foreach ($this->cacheKeys as $key) {
            $dropped[$key] = $this->peek($key);
            $this->cache->delete($key);
        }

        try {
            return $this->inner->getUserBadgeFrom($accessToken);
        } catch (BadCredentialsException $e) {
            if (null !== self::unreachable($e)) {
                foreach (array_filter($dropped, static fn (mixed $keys): bool => null !== $keys) as $key => $keys) {
                    $this->cache->get($key, static function (ItemInterface $item) use ($keys): mixed {
                        $item->expiresAfter(self::RESTORED_TTL);

                        return $keys;
                    });
                }
            }
            self::assertReachable($e);

            throw $e;
        }
    }

    /**
     * @throws KeycloakUnavailableException when the handler refused the token because it could not reach a provider
     */
    private static function assertReachable(BadCredentialsException $e): void
    {
        if (null !== $cause = self::unreachable($e)) {
            // Chained to the HTTP client's failure alone: to Symfony's security listener, a chain holding an authentication failure is a 401.
            throw new KeycloakUnavailableException('The OpenID provider\'s keys could not be fetched to verify the token: '.$cause->getMessage(), 0, $cause);
        }
    }

    /** The HTTP client's failure behind $e, when the handler could not reach a provider. */
    private static function unreachable(\Throwable $e): ?HttpClientException
    {
        for ($cause = $e->getPrevious(); null !== $cause; $cause = $cause->getPrevious()) {
            if ($cause instanceof HttpClientException) {
                return $cause;
            }
        }

        return null;
    }

    /** The cached value under $key, or null, without computing one. */
    private function peek(string $key): mixed
    {
        try {
            return $this->cache->get($key, static fn (): never => throw new \OutOfBoundsException());
        } catch (\OutOfBoundsException) {
            return null;
        }
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
