<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\DependencyInjection;

use Vinh0809it\KeycloakBundle\KeycloakBundle;
use Vinh0809it\KeycloakBundle\Security\ClaimsUserProvider;
use Vinh0809it\KeycloakBundle\Security\RealmTokenHandlerFactory;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\StatelessAuthenticatorFactoryInterface;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\Security\Http\AccessToken\ChainAccessTokenExtractor;
use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\AccessTokenAuthenticator;

/**
 * The `keycloak` authenticator of a firewall:
 *
 *     security:
 *         firewalls:
 *             main:
 *                 stateless: true
 *                 keycloak:
 *                     resolver: App\Security\MemberResolver
 *                     cookie: true
 *
 * Symfony's own access-token authenticator, the firewall's one for bearers: the token is verified
 * against the Keycloak realms the firewall accepts (declared under `keycloak`) and the other
 * OpenID providers it lists, then turned into the app's principal by a resolver. It brings its own
 * user provider, so the firewall's `provider` is not used by it.
 *
 * Every kind of bearer the firewall takes goes through it, as Symfony has one access-token
 * authenticator per firewall: another OpenID provider under `other_issuers`, a token the app issues
 * itself through a decorator of keycloak.token_handler.<firewall>.
 */
final class KeycloakAuthenticatorFactory implements StatelessAuthenticatorFactoryInterface
{
    /** Symfony's `access_token`'s, whose place it takes. */
    private const PRIORITY = -40;

    public function getPriority(): int
    {
        return self::PRIORITY;
    }

    public function getKey(): string
    {
        return 'keycloak';
    }

    public function addConfiguration(NodeDefinition $builder): void
    {
        \assert($builder instanceof ArrayNodeDefinition);

        $builder
            ->children()
                ->arrayNode('realms')
                    ->info('The keycloak realms whose tokens this firewall accepts; may be left out when only one is declared.')
                    ->scalarPrototype()->end()
                ->end()
                ->scalarNode('audience')
                    ->info('The `aud` a token must carry here; defaults to keycloak.audience.')
                    ->defaultNull()
                ->end()
                ->scalarNode('resolver')
                    ->info('Service id of the ClaimsResolverInterface for tokens no by_realm, by_client or other_issuers entry claims.')
                    ->defaultNull()
                ->end()
                ->arrayNode('by_realm')
                    ->info('Realm name (one of this firewall\'s realms) => resolver service id, for every token that realm issues.')
                    ->normalizeKeys(false)
                    ->useAttributeAsKey('realm')
                    ->scalarPrototype()->end()
                ->end()
                ->arrayNode('by_client')
                    ->info('Keycloak client id (the token\'s azp) => resolver service id.')
                    // Client ids are compared to `azp` verbatim: `admin-web` must not become `admin_web`.
                    ->normalizeKeys(false)
                    ->useAttributeAsKey('azp')
                    ->scalarPrototype()->end()
                ->end()
                ->booleanNode('cookie')
                    ->info('Also read the token from keycloak.cookies.access, after the Authorization header.')
                    ->defaultFalse()
                ->end()
                ->arrayNode('other_issuers')
                    ->info('OpenID providers other than the Keycloak realms whose tokens this firewall takes (another service\'s own tokens, say), each with the resolver of its principals.')
                    ->arrayPrototype()
                        ->children()
                            ->scalarNode('url')
                                ->info('Where its discovery document is, as this service reaches it. Empty: not configured, it takes no token.')
                                ->isRequired()
                            ->end()
                            ->scalarNode('issuer')
                                ->info('The `iss` its tokens carry, when it differs from `url`.')
                                ->defaultNull()
                            ->end()
                            ->scalarNode('resolver')
                                ->info('Service id of the ClaimsResolverInterface for its tokens.')
                                ->isRequired()
                                ->cannotBeEmpty()
                            ->end()
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('token_extractors')
                    ->info('Extractor service ids, tried in order, instead of the header (and cookie).')
                    ->scalarPrototype()->end()
                ->end()
                ->scalarNode('success_handler')
                    ->info('Service id of an AuthenticationSuccessHandlerInterface; by default the request goes on.')
                    ->defaultNull()
                ->end()
                ->scalarNode('failure_handler')
                    ->info('Service id of an AuthenticationFailureHandlerInterface; by default a 401 with a WWW-Authenticate header.')
                    ->defaultNull()
                ->end()
            ->end()
            ->validate()
                ->ifTrue(static fn (array $config): bool => null === $config['resolver'] && [] === $config['by_realm'] && [] === $config['by_client'] && [] === $config['other_issuers'])
                ->thenInvalid('The keycloak authenticator needs a "resolver", or entries under "by_realm", "by_client" or "other_issuers".')
            ->end()
            ->validate()
                ->ifTrue(static fn (array $config): bool => $config['cookie'] && [] !== $config['token_extractors'])
                ->thenInvalid('The keycloak authenticator takes "cookie" or "token_extractors", not both.')
            ->end();
    }

    /**
     * @param array{realms: list<string>, audience: ?string, resolver: ?string, by_realm: array<string, string>, by_client: array<string, string>, other_issuers: list<array{url: string, issuer: ?string, resolver: string}>, cookie: bool, token_extractors: list<string>, success_handler: ?string, failure_handler: ?string} $config
     */
    public function createAuthenticator(ContainerBuilder $container, string $firewallName, array $config, ?string $userProviderId): string
    {
        $handlerId = KeycloakBundle::TOKEN_HANDLER.$firewallName;
        $container->register($handlerId, AccessTokenHandlerInterface::class)
            ->setFactory([RealmTokenHandlerFactory::class, 'create'])
            ->setArguments([
                '$algorithms' => new Reference(KeycloakBundle::SIGNATURE_ALGORITHMS),
                '$http' => new Reference(KeycloakBundle::HTTP_CLIENT),
                '$discoveryCache' => new Reference(KeycloakBundle::DISCOVERY_CACHE),
                '$cacheKey' => KeycloakBundle::discoveryCacheKey($firewallName),
                // Realm names and the firewall's own audience until ResolveRealmsPass, which knows the realms.
                '$realms' => $config['realms'],
                '$audience' => $config['audience'],
                '$logger' => new Reference('logger', ContainerInterface::NULL_ON_INVALID_REFERENCE),
                '$otherIssuers' => array_map(static fn (array $provider): array => ['url' => $provider['url'], 'issuer' => $provider['issuer']], $config['other_issuers']),
            ])
            ->addTag(ResolveRealmsPass::TAG, ['firewall' => $firewallName, 'cookie' => $config['cookie']]);

        $byClient = [];
        foreach ($config['by_client'] as $azp => $resolver) {
            $byClient[$azp] = new Reference($resolver);
        }
        $providerId = KeycloakBundle::USER_PROVIDER.$firewallName;
        $byIssuer = [];
        foreach ($config['by_realm'] as $realm => $resolver) {
            // A realm's name until ResolveRealmsPass, which knows its URL and issuer.
            $byIssuer[] = ['provider' => (string) $realm, 'resolver' => new Reference($resolver)];
        }
        foreach ($config['other_issuers'] as $provider) {
            $byIssuer[] = [
                'provider' => ['url' => $provider['url'], 'issuer' => $provider['issuer']],
                'resolver' => new Reference($provider['resolver']),
            ];
        }
        $container->register($providerId, ClaimsUserProvider::class)
            ->setArguments([null !== $config['resolver'] ? new Reference($config['resolver']) : null, $byClient, $byIssuer]);

        $extractors = match (true) {
            [] !== $config['token_extractors'] => $config['token_extractors'],
            $config['cookie'] => [KeycloakBundle::TOKEN_EXTRACTOR_HEADER, KeycloakBundle::TOKEN_EXTRACTOR_COOKIE],
            default => [KeycloakBundle::TOKEN_EXTRACTOR_HEADER],
        };
        $extractorId = $extractors[0];
        if (1 < \count($extractors)) {
            $extractorId = KeycloakBundle::AUTHENTICATOR.$firewallName.'.token_extractor';
            $container->register($extractorId, ChainAccessTokenExtractor::class)
                ->setArguments([array_map(static fn (string $id): Reference => new Reference($id), $extractors)]);
        }

        $authenticatorId = KeycloakBundle::AUTHENTICATOR.$firewallName;
        $container->register($authenticatorId, AccessTokenAuthenticator::class)
            ->setArguments([
                '$accessTokenHandler' => new Reference($handlerId),
                '$accessTokenExtractor' => new Reference($extractorId),
                '$userProvider' => new Reference($providerId),
                '$successHandler' => self::handler($container, 'success', $config['success_handler'], $firewallName),
                '$failureHandler' => self::handler($container, 'failure', $config['failure_handler'], $firewallName),
            ]);

        return $authenticatorId;
    }

    /**
     * The app's handler wrapped as SecurityBundle wraps those of its own authenticators, which
     * hands it the firewall's name and options when it takes them.
     */
    private static function handler(ContainerBuilder $container, string $kind, ?string $serviceId, string $firewallName): ?Reference
    {
        if (null === $serviceId) {
            return null;
        }

        $id = KeycloakBundle::AUTHENTICATOR.$firewallName.'.'.$kind.'_handler';
        $definition = $container->setDefinition($id, new ChildDefinition('security.authentication.custom_'.$kind.'_handler'))
            ->replaceArgument(0, new Reference($serviceId))
            ->replaceArgument(1, []);
        if ('success' === $kind) {
            $definition->replaceArgument(2, $firewallName);
        }

        return new Reference($id);
    }
}
