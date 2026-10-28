<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Tests\Unit\Security;

use Vinh0809it\KeycloakBundle\Security\DevTokenHandler;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

final class DevTokenHandlerTest extends TestCase
{
    public function testAConfiguredBearerAnswersWithItsClaims(): void
    {
        $handler = new DevTokenHandler(self::inner(), [
            'user.1' => ['azp' => 'mobile-app', 'username' => 'user@example.com'],
            'admin.2' => ['sub' => 'b2', 'azp' => 'admin-web'],
        ]);

        $badge = $handler->getUserBadgeFrom('user.1');
        self::assertSame('user.1', $badge->getUserIdentifier(), 'sub defaults to the bearer');
        self::assertSame(['azp' => 'mobile-app', 'username' => 'user@example.com', 'sub' => 'user.1'], $badge->getAttributes());

        self::assertSame('b2', $handler->getUserBadgeFrom('admin.2')->getUserIdentifier());
    }

    public function testAnyOtherBearerGoesToTheRealVerifier(): void
    {
        $handler = new DevTokenHandler(self::inner(), ['user.1' => ['azp' => 'mobile-app']]);

        self::assertSame('verified:eyJ...', $handler->getUserBadgeFrom('eyJ...')->getUserIdentifier());
    }

    private static function inner(): AccessTokenHandlerInterface
    {
        return new class () implements AccessTokenHandlerInterface {
            public function getUserBadgeFrom(#[\SensitiveParameter] string $accessToken): UserBadge
            {
                return new UserBadge('verified:'.$accessToken);
            }
        };
    }
}
