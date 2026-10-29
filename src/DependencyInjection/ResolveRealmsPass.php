<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\DependencyInjection;

use Vinh0809it\KeycloakBundle\KeycloakBundle;
use Vinh0809it\KeycloakBundle\Security\DevTokenHandler;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Completes each `keycloak` firewall's token handler with what only keycloak knows: the realms
 * it named (or the only one declared) and the default audience; and puts the dev tokens in front
 * of it when there are any.
 *
 * A pass rather than the authenticator factory because the factory runs while the security
 * configuration is loaded, before keycloak's own configuration is guaranteed to be.
 */
final class ResolveRealmsPass implements CompilerPassInterface
{
    public const TAG = 'keycloak.token_handler';

    public function process(ContainerBuilder $container): void
    {
        $handlers = $container->findTaggedServiceIds(self::TAG);
        if ([] === $handlers) {
            return;
        }
        if (!$container->hasParameter(KeycloakBundle::REALMS_PARAMETER)) {
            throw new InvalidConfigurationException('A firewall uses the keycloak authenticator, but keycloak is not configured: declare its realm.');
        }

        /** @var array<string, array{url: string, issuer: ?string}> $realms */
        $realms = $container->getParameter(KeycloakBundle::REALMS_PARAMETER);
        /** @var ?string $audience */
        $audience = $container->getParameter(KeycloakBundle::AUDIENCE_PARAMETER);
        /** @var array<string, array<string, mixed>> $devTokens */
        $devTokens = $container->getParameter(KeycloakBundle::DEV_TOKENS_PARAMETER);

        foreach ($handlers as $id => $tags) {
            $firewall = (string) $tags[0]['firewall'];
            $handler = $container->getDefinition($id);

            self::assertStateless($container, $firewall);
            if (($tags[0]['cookie'] ?? false) && !$container->hasDefinition(KeycloakBundle::TOKEN_EXTRACTOR_COOKIE)) {
                throw new InvalidConfigurationException(\sprintf('security.firewalls.%s.keycloak reads the access cookie, which keycloak.cookies.access must name.', $firewall));
            }

            /** @var list<string> $names */
            $names = $handler->getArgument('$realms');
            $accepted = [];
            foreach ([] === $names ? [null] : $names as $name) {
                $accepted[] = $realms[KeycloakBundle::realmName($realms, $name, \sprintf('security.firewalls.%s.keycloak', $firewall))];
            }
            $handler->setArgument('$realms', $accepted);
            $handler->setArgument('$perIssuerKeys', '%'.KeycloakBundle::PER_ISSUER_KEYS_PARAMETER.'%');
            self::resolveRealmResolvers($container, $firewall, $realms, [] === $names ? [KeycloakBundle::realmName($realms, null, '')] : $names);
            $handler->setArgument('$audience', $handler->getArgument('$audience') ?? $audience
                ?? throw new InvalidConfigurationException(\sprintf('security.firewalls.%s.keycloak needs an "audience", or keycloak one.', $firewall)));

            if ([] !== $devTokens) {
                $container->register(KeycloakBundle::DEV_TOKEN_HANDLER.$firewall, DevTokenHandler::class)
                    ->setDecoratedService($id)
                    ->setArguments([new Reference('.inner'), $devTokens]);
            }
        }
    }

    /**
     * Replaces the realm names under the firewall's `by_realm` with those realms, which the user
     * provider matches a token's `iss` against.
     *
     * @param array<string, array{url: string, issuer: ?string}> $realms   every declared realm
     * @param list<string>                                       $accepted the realms the firewall accepts
     */
    private static function resolveRealmResolvers(ContainerBuilder $container, string $firewall, array $realms, array $accepted): void
    {
        $provider = $container->getDefinition(KeycloakBundle::USER_PROVIDER.$firewall);
        /** @var list<array{provider: string|array{url: string, issuer: ?string}, resolver: mixed}> $byIssuer */
        $byIssuer = $provider->getArgument(2);
        foreach ($byIssuer as $i => ['provider' => $realm]) {
            if (!\is_string($realm)) {
                continue;
            }
            if (!\in_array($realm, $accepted, true)) {
                throw new InvalidConfigurationException(\sprintf('security.firewalls.%s.keycloak.by_realm names "%s", which is not one of the firewall\'s realms (%s).', $firewall, $realm, implode(', ', $accepted)));
            }
            $byIssuer[$i]['provider'] = $realms[$realm];
        }
        $provider->setArgument(2, $byIssuer);
    }

    /**
     * The keycloak user provider rebuilds a principal from each request's token and cannot reload
     * one from a session, so a firewall keeping one would serve the roles of its first request
     * forever. The firewall's configuration is read from SecurityBundle's definition of it; should
     * that ever move, the check is skipped rather than guessed.
     */
    private static function assertStateless(ContainerBuilder $container, string $firewall): void
    {
        $id = 'security.firewall.map.config.'.$firewall;
        if (!$container->hasDefinition($id)) {
            return;
        }
        // SecurityExtension fills it in with replaceArgument(4, ...) on a child definition.
        if (false === ($container->getDefinition($id)->getArguments()['index_4'] ?? null)) {
            throw new InvalidConfigurationException(\sprintf('security.firewalls.%s uses the keycloak authenticator, which needs the firewall to be stateless: set "stateless: true".', $firewall));
        }
    }
}
