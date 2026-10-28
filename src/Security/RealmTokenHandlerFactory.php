<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Security;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use Psr\Log\LoggerInterface;
use Symfony\Component\Security\Http\AccessToken\Oidc\OidcTokenHandler;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Symfony's own `oidc` access-token handler, configured for the Keycloak realms and the other
 * OpenID providers one firewall accepts.
 *
 * Built at runtime rather than from the firewall's `oidc` block so the realm URLs can be normalised
 * after their env vars are resolved: discovery resolves `.well-known/openid-configuration` relative
 * to the base URI, so a realm URL without a trailing slash would lose its last segment; and the
 * issuer a token carries never has one. With several realms, Symfony binds each realm's keys to
 * the issuer its own discovery document announces, so one realm's keys never verify another's
 * tokens.
 *
 * A realm whose URL is empty (its env var unset, as in a dev setup living on dev tokens) is not
 * configured: no token names it, so it gets no discovery, and verifying a token fails rather than
 * building the handler.
 */
final class RealmTokenHandlerFactory
{
    /** The asymmetric algorithms an OpenID provider signs access tokens with, as Symfony's `oidc` handler takes them. */
    public const array ALGORITHMS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512'];

    /**
     * @param list<value-of<self::ALGORITHMS>> $names
     */
    public static function algorithms(array $names): AlgorithmManager
    {
        return new AlgorithmManager(array_map(
            static fn (string $name): SignatureAlgorithm => new ('Jose\\Component\\Signature\\Algorithm\\'.$name)(),
            $names,
        ));
    }

    /**
     * @param list<array{url: string, issuer: ?string}> $realms       each realm's URL as this service reaches it, and as tokens name it in `iss` when that differs (a public host)
     * @param list<array{url: string, issuer: ?string}> $otherIssuers the same for the other OpenID providers the firewall accepts
     */
    public static function create(
        AlgorithmManager $algorithms,
        HttpClientInterface $http,
        CacheInterface $discoveryCache,
        string $cacheKey,
        array $realms,
        string $audience,
        ?LoggerInterface $logger = null,
        array $otherIssuers = [],
    ): OidcTokenHandler {
        $realms = array_values(array_filter([...$realms, ...$otherIssuers], static fn (array $realm): bool => '' !== $realm['url']));
        $handler = new OidcTokenHandler($algorithms, null, $audience, array_map(self::issuer(...), $realms), 'sub', $logger);
        if ([] !== $realms) {
            $handler->enableDiscovery($discoveryCache, array_map(static fn (array $realm): HttpClientInterface => $http->withOptions(['base_uri' => rtrim($realm['url'], '/').'/']), $realms), $cacheKey);
        }

        return $handler;
    }

    /**
     * The `iss` a realm's tokens carry: its issuer when it has one (a public host), else its URL.
     *
     * @param array{url: string, issuer: ?string} $realm
     */
    public static function issuer(array $realm): string
    {
        return rtrim('' !== (string) $realm['issuer'] ? (string) $realm['issuer'] : $realm['url'], '/');
    }

    /**
     * The issuers of the configured realms among $realms: a realm whose URL is empty names none.
     *
     * @param list<array{url: string, issuer: ?string}> $realms
     *
     * @return list<string>
     */
    public static function issuers(array $realms): array
    {
        return array_values(array_map(self::issuer(...), array_filter($realms, static fn (array $realm): bool => '' !== $realm['url'])));
    }
}
