<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Tests\Functional\App;

use Vinh0809it\KeycloakBundle\KeycloakBundle;
use Vinh0809it\KeycloakBundle\Test\KeycloakStub;
use Vinh0809it\KeycloakBundle\Test\KeycloakStubRouter;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Attribute\CurrentUser;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/**
 * Two realms and two firewalls: `members` accepts the members realm only and answers a refused
 * token with its own failure handler; `main` accepts both, resolves the staff realm's tokens by
 * realm, takes a legacy OpenID provider beside them, and the app's own tokens through a decorator
 * of its token handler. Each provider is a stub with its own signing key, routed to by URL.
 */
final class TestKernel extends Kernel
{
    use MicroKernelTrait;

    public const MEMBERS = 'https://keycloak.test/realms/members';
    public const STAFF = 'https://keycloak.test/realms/staff';
    /** Another service's own OpenID provider: not a Keycloak realm. */
    public const LEGACY = 'https://legacy.test';

    public function registerBundles(): iterable
    {
        yield new FrameworkBundle();
        yield new SecurityBundle();
        yield new KeycloakBundle();
    }

    public function getProjectDir(): string
    {
        return __DIR__;
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir().'/keycloak-bundle-test/'.\PHP_VERSION_ID.'/cache';
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir().'/keycloak-bundle-test/'.\PHP_VERSION_ID.'/log';
    }

    public function whoami(#[CurrentUser] UserInterface $user): JsonResponse
    {
        return new JsonResponse(['user' => $user->getUserIdentifier()]);
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->add('whoami', '/whoami')->controller('kernel::whoami');
        $routes->add('members_whoami', '/members/whoami')->controller('kernel::whoami');
    }

    protected function configureContainer(ContainerConfigurator $container): void
    {
        $container->extension('framework', [
            'test' => true,
            'secret' => 'test',
            'http_method_override' => false,
            'handle_all_throwables' => true,
            'http_client' => ['mock_response_factory' => KeycloakStubRouter::class],
        ]);

        $container->extension('security', [
            'firewalls' => [
                'members' => [
                    'pattern' => '^/members',
                    'stateless' => true,
                    'keycloak' => ['realms' => ['members'], 'resolver' => 'test.member_resolver', 'failure_handler' => JsonFailureHandler::class],
                ],
                'main' => [
                    'stateless' => true,
                    'keycloak' => [
                        'realms' => ['members', 'staff'],
                        'resolver' => 'test.member_resolver',
                        'by_realm' => ['staff' => 'test.staff_resolver'],
                        'by_client' => ['staff-web' => 'test.staff_resolver'],
                        'other_issuers' => [['url' => self::LEGACY, 'resolver' => 'test.legacy_resolver']],
                        'cookie' => true,
                    ],
                ],
            ],
            'access_control' => [['path' => '^/', 'roles' => 'IS_AUTHENTICATED_FULLY']],
        ]);

        $container->extension('keycloak', [
            'audience' => 'api',
            'realms' => [
                // A trailing slash on the URL, none on the issuer a token carries: the bundle reconciles them.
                'members' => ['url' => self::MEMBERS.'/'],
                'staff' => ['url' => self::STAFF],
            ],
            'cookies' => ['access' => ['name' => 'access_token'], 'refresh' => ['name' => 'refresh_token', 'path' => '/session']],
            'dev_tokens' => ['dev.staff' => ['azp' => 'staff-web']],
        ]);

        $services = $container->services();
        // Symfony's fallback logger writes to stderr, which PHPUnit reports as test output.
        $services->set('logger', \Psr\Log\NullLogger::class);
        $services->set('test.member_resolver', PrefixResolver::class)->args(['member']);
        $services->set('test.staff_resolver', PrefixResolver::class)->args(['staff']);
        foreach (['members' => self::MEMBERS, 'staff' => self::STAFF, 'legacy' => self::LEGACY] as $name => $issuer) {
            $services->set('test.realm.'.$name, KeycloakStub::class)
                ->args([$issuer, param('kernel.cache_dir'), service('cache.app'), ['main', 'members']])
                ->public();
        }
        $services->set('test.legacy_resolver', PrefixResolver::class)->args(['legacy']);
        $services->set(JsonFailureHandler::class);
        $services->set(OwnTokenHandler::class)
            ->decorate(KeycloakBundle::TOKEN_HANDLER.'main')
            ->args([service('.inner')]);
        $services->set(KeycloakStubRouter::class)->args([service('test.realm.members'), service('test.realm.staff'), service('test.realm.legacy')]);
    }
}
