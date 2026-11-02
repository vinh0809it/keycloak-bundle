<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Tests\Unit\Security;

use Vinh0809it\KeycloakBundle\Security\Claims;
use Vinh0809it\KeycloakBundle\Security\ClaimsResolverInterface;
use Vinh0809it\KeycloakBundle\Security\ClaimsUserProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\UserInterface;

final class ClaimsUserProviderTest extends TestCase
{
    public function testRoutesByTheTokensClientBeforeTheDefault(): void
    {
        $provider = new ClaimsUserProvider(self::resolver('default'), ['admin-web' => self::resolver('admin')]);

        self::assertSame('admin', $provider->loadUserByIdentifier('s', ['azp' => 'admin-web'])->getUserIdentifier());
        self::assertSame('default', $provider->loadUserByIdentifier('s', ['azp' => 'mobile-app'])->getUserIdentifier());
        self::assertSame('default', $provider->loadUserByIdentifier('s', [])->getUserIdentifier(), 'a token with no azp is the default resolver\'s');
    }

    public function testATokenOfAnotherIssuerGoesToThatIssuersResolverWhateverItsClient(): void
    {
        $provider = new ClaimsUserProvider(self::resolver('default'), ['mobile-app' => self::resolver('client')], [
            ['provider' => ['url' => 'http://legacy.local/', 'issuer' => 'https://legacy.test'], 'resolver' => self::resolver('legacy'), 'byClient' => []],
            ['provider' => ['url' => '', 'issuer' => ''], 'resolver' => self::resolver('unconfigured'), 'byClient' => []],
        ]);

        self::assertSame('legacy', $provider->loadUserByIdentifier('s', ['iss' => 'https://legacy.test', 'azp' => 'mobile-app'])->getUserIdentifier());
        self::assertSame('client', $provider->loadUserByIdentifier('s', ['iss' => 'https://kc/realms/a', 'azp' => 'mobile-app'])->getUserIdentifier());
        self::assertSame('default', $provider->loadUserByIdentifier('s', ['iss' => ''])->getUserIdentifier(), 'an unconfigured issuer names no token');
    }

    public function testARealmsTokenIsPickedAmongThatRealmsResolversAlone(): void
    {
        $provider = new ClaimsUserProvider(self::resolver('default'), ['web' => self::resolver('member-web'), 'mobile-app' => self::resolver('mobile')], [
            ['provider' => ['url' => 'http://kc/realms/employees', 'issuer' => null], 'resolver' => null, 'byClient' => ['web' => self::resolver('staff-web')]],
            ['provider' => ['url' => 'http://kc/realms/partners', 'issuer' => null], 'resolver' => self::resolver('partner'), 'byClient' => ['web' => self::resolver('partner-web')]],
        ]);
        $employees = ['iss' => 'http://kc/realms/employees'];
        $partners = ['iss' => 'http://kc/realms/partners'];

        self::assertSame('staff-web', $provider->loadUserByIdentifier('s', $employees + ['azp' => 'web'])->getUserIdentifier(), 'the same client id, told apart by its realm');
        self::assertSame('member-web', $provider->loadUserByIdentifier('s', ['iss' => 'http://kc/realms/customers', 'azp' => 'web'])->getUserIdentifier());
        self::assertSame('partner-web', $provider->loadUserByIdentifier('s', $partners + ['azp' => 'web'])->getUserIdentifier());
        self::assertSame('partner', $provider->loadUserByIdentifier('s', $partners + ['azp' => 'mobile-app'])->getUserIdentifier(), 'the realm\'s own default, not the firewall\'s by_client');

        $this->expectException(UserNotFoundException::class);
        $provider->loadUserByIdentifier('s', $employees + ['azp' => 'mobile-app']);
    }

    public function testAClientWithNoResolverAndNoDefaultIsRefused(): void
    {
        $provider = new ClaimsUserProvider(null, ['admin-web' => self::resolver('admin')]);

        $this->expectException(UserNotFoundException::class);

        $provider->loadUserByIdentifier('s', ['azp' => 'mobile-app']);
    }

    public function testTheResolverSeesTheClaims(): void
    {
        $seen = null;
        $resolver = new class ($seen) implements ClaimsResolverInterface {
            public function __construct(private ?Claims &$seen)
            {
            }

            public function resolve(Claims $claims): UserInterface
            {
                $this->seen = $claims;

                return new InMemoryUser($claims->sub, null);
            }
        };

        (new ClaimsUserProvider($resolver))->loadUserByIdentifier('sub-1', ['azp' => 'mobile-app', 'username' => '+1']);

        self::assertInstanceOf(Claims::class, $seen);
        self::assertSame('sub-1', $seen->sub);
        self::assertSame('+1', $seen->string('username'));
    }

    public function testAStatelessFirewallRefreshesNothing(): void
    {
        $user = new InMemoryUser('u', null);
        $provider = new ClaimsUserProvider(self::resolver('default'));

        self::assertSame($user, $provider->refreshUser($user));
        self::assertTrue($provider->supportsClass(InMemoryUser::class));
    }

    private static function resolver(string $name): ClaimsResolverInterface
    {
        return new class ($name) implements ClaimsResolverInterface {
            public function __construct(private readonly string $name)
            {
            }

            public function resolve(Claims $claims): UserInterface
            {
                return new InMemoryUser($this->name, null);
            }
        };
    }
}
