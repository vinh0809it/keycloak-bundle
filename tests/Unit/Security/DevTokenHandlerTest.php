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

    public function testAPatternTakesAnyBearerOfItsShapeAndSetsItsPlaceholdersAsClaims(): void
    {
        $handler = new DevTokenHandler(self::inner(), [
            'user.1' => ['azp' => 'mobile-app'],
            '{azp}~{sub}' => ['email_verified' => true],
        ]);

        $badge = $handler->getUserBadgeFrom('admin-web~42');
        self::assertSame('42', $badge->getUserIdentifier());
        self::assertSame(['azp' => 'admin-web', 'sub' => '42', 'email_verified' => true], $badge->getAttributes());
        self::assertSame('user.1', $handler->getUserBadgeFrom('user.1')->getUserIdentifier(), 'a literal bearer is matched as such');
        self::assertSame('verified:eyJ.e30.sig', $handler->getUserBadgeFrom('eyJ.e30.sig')->getUserIdentifier(), 'a JWT is not of its shape');
    }

    public function testAPatternIsSafeOnlyWithACharacterNoJwtHolds(): void
    {
        self::assertTrue(DevTokenHandler::isSafePattern('{azp}~{sub}'));
        self::assertTrue(DevTokenHandler::isSafePattern('user:{sub}'));
        self::assertFalse(DevTokenHandler::isSafePattern('{sub}'));
        self::assertFalse(DevTokenHandler::isSafePattern('user.{sub}'));
        self::assertFalse(DevTokenHandler::isSafePattern('{a}.{b}.{c}'));
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
