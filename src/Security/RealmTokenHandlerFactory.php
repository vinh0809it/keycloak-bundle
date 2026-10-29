<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Security;

use Composer\InstalledVersions;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use Psr\Log\LoggerInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;
use Symfony\Component\Security\Http\AccessToken\Oidc\OidcTokenHandler;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Symfony's own `oidc` access-token handler, configured for the Keycloak realms and the other
 * OpenID providers one firewall accepts.
 *
 * Built at runtime rather than from the firewall's `oidc` block so the realm URLs can be normalised
 * after their env vars are resolved: discovery resolves `.well-known/openid-configuration` relative
 * to the base URI, so a realm URL without a trailing slash would lose its last segment. An issuer
 * derived from the URL has no trailing slash, as Keycloak's do not; one configured explicitly is
 * taken exactly as written. From symfony/security-http 7.4.20 / 8.1.8 on, Symfony binds each
 * provider's keys to the issuer its own discovery document announces, so one provider's keys never
 * verify another's tokens.
 *
 * A realm whose URL is empty (its env var unset, as in a dev setup living on dev tokens) is not
 * configured: no token names it and it gets no discovery. A firewall left with no provider at all
 * refuses every token it is handed.
 */
final class RealmTokenHandlerFactory
{
    /** The asymmetric algorithms an OpenID provider signs access tokens with, as Symfony's `oidc` handler takes them. */
    public const ALGORITHMS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512'];

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

    /** Whether the warning about a shared key set has been logged in this process. */
    private static bool $warned = false;

    /**
     * @param list<array{url: string, issuer: ?string}> $realms        each realm's URL as this service reaches it, and as tokens name it in `iss` when that differs (a public host)
     * @param list<array{url: string, issuer: ?string}> $otherIssuers  the same for the other OpenID providers the firewall accepts
     * @param bool|null                                 $perIssuerKeys whether Symfony binds each provider's keys to its issuer; detected when null
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
        ?bool $perIssuerKeys = null,
    ): AccessTokenHandlerInterface {
        $realms = array_values(array_filter([...$realms, ...$otherIssuers], static fn (array $realm): bool => '' !== $realm['url']));
        if (1 < \count($realms) && !self::$warned && !($perIssuerKeys ?? self::perIssuerKeys())) {
            self::$warned = true;
            $logger?->warning('symfony/security-http {version} verifies a token against the keys of every provider on the firewall ({issuers}), whatever its "iss": the private key of any one of them can sign tokens claiming another. Upgrade to 7.4.20 or 8.1.8, where each provider\'s keys verify only its own tokens.', [
                'version' => InstalledVersions::getPrettyVersion('symfony/security-http'),
                'issuers' => implode(', ', array_map(self::issuer(...), $realms)),
            ]);
        }
        if ([] === $realms) {
            return new class () implements AccessTokenHandlerInterface {
                public function getUserBadgeFrom(#[\SensitiveParameter] string $accessToken): UserBadge
                {
                    throw new BadCredentialsException('No OpenID provider is configured on this firewall.');
                }
            };
        }

        $handler = new OidcTokenHandler($algorithms, null, $audience, array_map(self::issuer(...), $realms), 'sub', $logger);
        $handler->enableDiscovery($discoveryCache, array_map(static fn (array $realm): HttpClientInterface => $http->withOptions(['base_uri' => rtrim($realm['url'], '/').'/']), $realms), $cacheKey);

        // Symfony caches one provider's keys under the key itself, several under ".issuer_keysets".
        return new KeyRotationTokenHandler($handler, $discoveryCache, [$cacheKey, $cacheKey.'.issuer_keysets'], $cacheKey.'.refetched', $logger);
    }

    /**
     * Whether the installed symfony/security-http binds each discovered provider's keys to its own
     * issuer: from 7.4.20 on 7.4, and from 8.1.8 on 8.x. Unknown (not installed through Composer)
     * counts as yes.
     */
    public static function perIssuerKeys(): bool
    {
        $version = InstalledVersions::isInstalled('symfony/security-http') ? InstalledVersions::getVersion('symfony/security-http') : null;
        if (null === $version) {
            return true;
        }

        return version_compare($version, '8.0.0', '<')
            ? version_compare($version, '7.4.20', '>=')
            : version_compare($version, '8.1.8', '>=');
    }

    /**
     * The `iss` a realm's tokens carry: its issuer exactly as configured when it has one (a public
     * host), else its URL without a trailing slash.
     *
     * @param array{url: string, issuer: ?string} $realm
     */
    public static function issuer(array $realm): string
    {
        return '' !== (string) $realm['issuer'] ? (string) $realm['issuer'] : rtrim($realm['url'], '/');
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
