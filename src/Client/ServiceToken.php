<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Client;

use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

/**
 * The access token of a confidential client's own service account, for calling another service as
 * this one. Minted by the client-credentials grant and reused for its lifetime minus a margin, so
 * nothing sends one about to expire mid-request.
 *
 * Without a cache pool the token lives as long as this object: a whole run of a command, but only
 * one request under php-fpm, where the container is rebuilt per request. With one, every request
 * and every worker share it until it nearly expires.
 */
final class ServiceToken
{
    private const EXPIRY_MARGIN = 30;

    private ?string $token = null;
    private int $expiresAt = 0;

    /**
     * @param \Closure(): int|null $clock    the current Unix time; time() when null
     * @param string               $cacheKey the pool key, one per client
     */
    public function __construct(
        private readonly KeycloakClient $client,
        private readonly ?\Closure $clock = null,
        private readonly ?CacheInterface $cache = null,
        private readonly string $cacheKey = 'keycloak.service_token',
    ) {
    }

    /**
     * @throws Exception\KeycloakException
     */
    public function get(): string
    {
        $now = null !== $this->clock ? ($this->clock)() : time();
        if (null !== $this->token && $now < $this->expiresAt - self::EXPIRY_MARGIN) {
            return $this->token;
        }

        [$this->token, $this->expiresAt] = null === $this->cache
            ? $this->mint($now)
            : $this->cache->get($this->cacheKey, function (ItemInterface $item) use ($now): array {
                $minted = $this->mint($now);
                $item->expiresAfter(max(1, $minted[1] - $now - self::EXPIRY_MARGIN));

                return $minted;
            });

        // A cached token another process minted may already be near its end.
        if ($now >= $this->expiresAt - self::EXPIRY_MARGIN) {
            $this->cache?->delete($this->cacheKey);
            [$this->token, $this->expiresAt] = $this->mint($now);
        }

        return $this->token;
    }

    /**
     * @return array{string, int} the token and when it expires
     */
    private function mint(int $now): array
    {
        $tokens = $this->client->clientCredentials();

        return [$tokens->accessToken, $now + $tokens->expiresIn];
    }
}
