<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Tests\Unit\Security;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;
use Symfony\Component\Security\Http\AccessToken\Oidc\Exception\InvalidSignatureException;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Vinh0809it\KeycloakBundle\Security\KeyRotationTokenHandler;

final class KeyRotationTokenHandlerTest extends TestCase
{
    private ArrayAdapter $cache;

    protected function setUp(): void
    {
        $this->cache = new ArrayAdapter();
    }

    public function testATokenNoCachedKeyVerifiesIsVerifiedAgainstFreshKeys(): void
    {
        $this->cache->get('keys', static fn (): string => 'old');

        $badge = $this->handler()->getUserBadgeFrom('signed-by-new');

        self::assertSame('user', $badge->getUserIdentifier());
        self::assertSame('new', $this->cache->get('keys', static fn (): string => 'new'), 'the keys were fetched afresh');
    }

    public function testKeysAreRefetchedAtMostOncePerInterval(): void
    {
        $this->cache->get('keys', static fn (): string => 'old');
        $handler = $this->handler();
        $handler->getUserBadgeFrom('signed-by-new');
        $this->cache->delete('keys');
        $this->cache->get('keys', static fn (): string => 'old');

        $this->expectException(BadCredentialsException::class);
        $handler->getUserBadgeFrom('signed-by-new');
    }

    public function testAnyOtherRefusalLeavesTheKeysAlone(): void
    {
        $this->cache->get('keys', static fn (): string => 'old');

        try {
            $this->handler()->getUserBadgeFrom('expired');
            self::fail('An expired token was accepted.');
        } catch (BadCredentialsException) {
        }

        self::assertSame('old', $this->cache->get('keys', static fn (): string => 'new'));
    }

    /** A verifier over the `keys` cache entry: `old` keys verify no token signed by the new key. */
    private function handler(): KeyRotationTokenHandler
    {
        $cache = $this->cache;
        $inner = new class ($cache) implements AccessTokenHandlerInterface {
            public function __construct(private ArrayAdapter $cache)
            {
            }

            public function getUserBadgeFrom(#[\SensitiveParameter] string $accessToken): UserBadge
            {
                if ('expired' === $accessToken) {
                    throw new BadCredentialsException('Invalid credentials.');
                }
                if ('new' !== $this->cache->get('keys', static fn (): string => 'new')) {
                    throw new BadCredentialsException('Invalid credentials.', 0, new InvalidSignatureException());
                }

                return new UserBadge('user');
            }
        };

        return new KeyRotationTokenHandler($inner, $cache, ['keys', 'keys.issuer_keysets'], 'keys.refetched');
    }
}
