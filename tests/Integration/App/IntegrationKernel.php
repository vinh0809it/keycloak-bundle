<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Tests\Integration\App;

use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Attribute\CurrentUser;
use Vinh0809it\KeycloakBundle\KeycloakBundle;
use Vinh0809it\KeycloakBundle\Tests\Functional\App\PrefixResolver;

/**
 * One firewall on the `demo` realm of a real Keycloak (tests/Integration/realm.json), at the URL in
 * KEYCLOAK_URL: users resolve as `user:<sub>`, the demo-service account as `service:<sub>`.
 */
final class IntegrationKernel extends Kernel
{
    use MicroKernelTrait;

    public static function realm(): string
    {
        return rtrim((string) getenv('KEYCLOAK_URL'), '/').'/realms/demo';
    }

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
        return sys_get_temp_dir().'/keycloak-bundle-test/'.\PHP_VERSION_ID.'/integration/cache';
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir().'/keycloak-bundle-test/'.\PHP_VERSION_ID.'/integration/log';
    }

    public function whoami(#[CurrentUser] UserInterface $user): JsonResponse
    {
        return new JsonResponse(['user' => $user->getUserIdentifier()]);
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->add('whoami', '/whoami')->controller('kernel::whoami');
    }

    protected function configureContainer(ContainerConfigurator $container): void
    {
        $container->extension('framework', [
            'test' => true,
            'secret' => 'test',
            'http_method_override' => false,
            'handle_all_throwables' => true,
        ]);

        $container->extension('security', [
            'firewalls' => [
                'main' => [
                    'stateless' => true,
                    'keycloak' => [
                        'resolver' => 'test.user_resolver',
                        'by_client' => ['demo-service' => 'test.service_resolver'],
                    ],
                ],
            ],
            'access_control' => [['path' => '^/', 'roles' => 'IS_AUTHENTICATED_FULLY']],
        ]);

        $container->extension('keycloak', [
            'realm' => self::realm(),
            'audience' => 'demo-api',
            'discovery_cache' => 'cache.app',
        ]);

        $services = $container->services();
        $services->set('logger', \Psr\Log\NullLogger::class);
        $services->set('test.user_resolver', PrefixResolver::class)->args(['user']);
        $services->set('test.service_resolver', PrefixResolver::class)->args(['service']);
    }
}
