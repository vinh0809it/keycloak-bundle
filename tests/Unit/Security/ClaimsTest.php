<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Tests\Unit\Security;

use Vinh0809it\KeycloakBundle\Security\Claims;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

final class ClaimsTest extends TestCase
{
    public function testTypesTheStandardClaims(): void
    {
        $claims = Claims::fromAttributes('sub-1', [
            'iss' => 'https://keycloak.test/realms/customers',
            'azp' => 'mobile-app',
            'aud' => ['my-api', 'other-api'],
            'realm_access' => ['roles' => ['member', 'offline_access']],
            'resource_access' => ['other-api' => ['roles' => ['reader']]],
            'username' => 'user@example.com',
        ]);

        self::assertSame('sub-1', $claims->sub);
        self::assertSame('https://keycloak.test/realms/customers', $claims->issuer);
        self::assertSame('mobile-app', $claims->client);
        self::assertSame(['my-api', 'other-api'], $claims->audience);
        self::assertSame(['member', 'offline_access'], $claims->realmRoles);
        self::assertSame(['other-api' => ['reader']], $claims->clientRoles);
        self::assertSame('user@example.com', $claims->string('username'));
        self::assertTrue($claims->has('username'));
    }

    public function testAStringAudienceBecomesAList(): void
    {
        self::assertSame(['my-api'], Claims::fromAttributes('s', ['aud' => 'my-api'])->audience);
    }

    public function testATokenWithoutAClientHasNone(): void
    {
        $claims = Claims::fromAttributes('s', ['iss' => 'https://my-api.test']);

        self::assertNull($claims->client);
        self::assertSame([], $claims->audience);
        self::assertSame([], $claims->realmRoles);
        self::assertNull($claims->stringOrNull('username'));
        self::assertNull($claims->get('username'));
        self::assertSame([], $claims->list('groups'));
    }

    public function testARequiredClaimThatIsMissingIsACredentialsProblem(): void
    {
        $this->expectException(BadCredentialsException::class);

        Claims::fromAttributes('s', ['username' => ''])->string('username');
    }

    public function testRolesAreTheRealmsAndOneClientsAsSymfonyRoles(): void
    {
        $claims = Claims::fromAttributes('s', [
            'realm_access' => ['roles' => ['offline_access', 'member']],
            'resource_access' => ['my-api' => ['roles' => ['order-admin', 'member']], 'other' => ['roles' => ['x']]],
        ]);

        self::assertSame(['ROLE_OFFLINE_ACCESS', 'ROLE_MEMBER'], $claims->roles());
        self::assertSame(['ROLE_OFFLINE_ACCESS', 'ROLE_MEMBER', 'ROLE_ORDER_ADMIN'], $claims->roles('my-api'));
        self::assertSame(['KC_OFFLINE_ACCESS', 'KC_MEMBER'], $claims->roles(prefix: 'KC_'));
    }
}
