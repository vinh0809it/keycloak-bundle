<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Test;

use Vinh0809it\KeycloakBundle\KeycloakBundle;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * A Keycloak realm as far as a resource server can tell, for the test suite: OIDC discovery and a
 * JWKS, so the firewall's real `oidc` handler verifies tokens this stub signs; the
 * client-credentials grant of the confidential clients registered with {@see serviceClient()}; and
 * whatever realm endpoints and grants the app or an SPI's test helper registers with {@see on()}
 * and {@see onGrant()}. Wire it as the `mock_response_factory` of the test environment's HTTP
 * clients, so the discovery client the token handler uses answers from here too.
 *
 * A subclass may keep the app's constants and helpers and answer its own grants in {@see grant()},
 * so the test files need not know the stub is shared.
 *
 * The signing key is generated once per cache dir and kept on disk, because the verifier caches
 * the discovered keys in the pool it was configured with: a fresh key per process would fail every
 * token minted after the first run. Generating one also drops the realm's entry from that pool.
 */
class KeycloakStub
{
    public const string KEY_ID = 'stub';

    /** @var list<array<string, mixed>> every form body Keycloak received, with the request path as `_path` */
    public static array $requests = [];

    /** @var array<string, JWK> issuer => its signing key: each realm signs with its own */
    private static array $keys = [];

    /** @var array<string, array<string, mixed>> client id => the claims of its service account's token */
    private array $serviceClients = [];

    /** @var list<array{string, string, callable(array<string, mixed>, array<string, mixed>): MockResponse}> method, path suffix, handler */
    private array $routes = [];

    /** @var list<callable(array<string, mixed>): ?MockResponse> */
    private array $grants = [];

    /**
     * @param CacheItemPoolInterface $discoveryCache the pool keycloak.discovery_cache names (cache.app by default)
     * @param list<string>           $firewalls      the firewalls whose handler discovers this realm, for the keys they cache
     */
    public function __construct(
        private readonly string $issuer,
        private readonly string $cacheDir,
        private readonly CacheItemPoolInterface $discoveryCache,
        private readonly array $firewalls = ['main'],
    ) {
    }

    public static function reset(): void
    {
        self::$requests = [];
    }

    /**
     * A confidential client whose client-credentials grant answers with a token carrying $claims
     * (`sub`, `azp`, `aud`...). Any other client or grant on the token endpoint goes to {@see grant()}.
     *
     * @param array<string, mixed> $claims
     */
    final public function serviceClient(string $clientId, array $claims): void
    {
        $this->serviceClients[$clientId] = $claims;
    }

    /**
     * Answers $method requests whose path ends with $suffix, after the built-in endpoints.
     *
     * @param callable(array<string, mixed> $form, array<string, mixed> $options): MockResponse $handler
     */
    final public function on(string $method, string $suffix, callable $handler): void
    {
        $this->routes[] = [strtoupper($method), $suffix, $handler];
    }

    /**
     * Answers the token requests $handler recognises (an SPI authenticator's direct grant, say):
     * it returns null for one that is not its own, which goes on to the next handler, then to
     * {@see grant()}. Registered service clients are answered before any of them.
     *
     * @param callable(array<string, mixed> $form): ?MockResponse $handler
     */
    final public function onGrant(callable $handler): void
    {
        $this->grants[] = $handler;
    }

    /**
     * @param array<string, mixed> $options
     */
    public function __invoke(string $method, string $url, array $options): MockResponse
    {
        $path = (string) parse_url($url, \PHP_URL_PATH);
        parse_str((string) ($options['body'] ?? ''), $form);
        self::$requests[] = $form + ['_path' => $path];

        if (str_ends_with($path, '/.well-known/openid-configuration')) {
            return self::json(['issuer' => $this->issuer, 'jwks_uri' => $this->issuer.'/protocol/openid-connect/certs']);
        }
        if (str_ends_with($path, '/protocol/openid-connect/certs')) {
            return self::json(['keys' => [$this->key()->toPublic()->jsonSerialize()]]);
        }
        if (str_ends_with($path, '/protocol/openid-connect/token')) {
            return $this->token($form);
        }
        foreach ($this->routes as [$routeMethod, $suffix, $handler]) {
            if ($routeMethod === strtoupper($method) && str_ends_with($path, $suffix)) {
                return $handler($form, $options);
            }
        }

        return new MockResponse('', ['http_code' => 404]);
    }

    /**
     * A token the verifier accepts: $claims signed with the realm's key, `iss`, `iat` and `exp`
     * filled in when absent.
     *
     * @param array<string, mixed> $claims
     */
    final public function sign(array $claims): string
    {
        $now = time();
        $payload = $claims + ['iss' => $this->issuer, 'iat' => $now, 'exp' => $now + 300];

        $jws = (new JWSBuilder(new AlgorithmManager([new RS256()])))
            ->create()
            ->withPayload((string) json_encode($payload, \JSON_THROW_ON_ERROR))
            ->addSignature($this->key(), ['alg' => 'RS256', 'kid' => self::KEY_ID])
            ->build();

        return (new CompactSerializer())->serialize($jws);
    }

    /**
     * The token endpoint for every request that is not a registered service client's
     * client-credentials grant. Return null for a client or grant the app does not serve, which
     * Keycloak answers as an unauthorized client.
     *
     * @param array<string, mixed> $form
     */
    protected function grant(array $form): ?MockResponse
    {
        return null;
    }

    /**
     * @param array<string, mixed> $body
     */
    final protected static function json(array $body, int $status = 200): MockResponse
    {
        return new MockResponse((string) json_encode($body, \JSON_THROW_ON_ERROR), [
            'http_code' => $status,
            'response_headers' => ['content-type' => 'application/json'],
        ]);
    }

    /**
     * @param array<string, mixed> $form
     */
    private function token(array $form): MockResponse
    {
        $clientId = (string) ($form['client_id'] ?? '');
        $claims = $this->serviceClients[$clientId] ?? null;

        if (null !== $claims) {
            // A refused client-credentials grant is the caller's configuration — a wrong secret,
            // a client without a service account — and Keycloak answers it as such.
            if ('client_credentials' !== ($form['grant_type'] ?? null) || '' === (string) ($form['client_secret'] ?? '')) {
                return self::json(['error' => 'unauthorized_client'], 401);
            }

            return self::json(['access_token' => $this->sign($claims), 'token_type' => 'Bearer', 'expires_in' => 300]);
        }

        foreach ($this->grants as $handler) {
            $response = $handler($form);
            if (null !== $response) {
                return $response;
            }
        }

        return $this->grant($form) ?? self::json(['error' => 'unauthorized_client'], 401);
    }

    private function key(): JWK
    {
        if (isset(self::$keys[$this->issuer])) {
            return self::$keys[$this->issuer];
        }

        $file = $this->cacheDir.'/keycloak-stub.'.md5($this->issuer).'.jwk.json';
        if (is_file($file)) {
            return self::$keys[$this->issuer] = new JWK((array) json_decode((string) file_get_contents($file), true));
        }

        $key = self::$keys[$this->issuer] = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig', 'kid' => self::KEY_ID]);
        @mkdir($this->cacheDir, 0o777, true);
        file_put_contents($file, json_encode($key->jsonSerialize()));
        foreach ($this->firewalls as $firewall) {
            // One realm caches its keys under the key itself; several, under its ".issuer_keysets".
            $this->discoveryCache->deleteItem(KeycloakBundle::discoveryCacheKey($firewall));
            $this->discoveryCache->deleteItem(KeycloakBundle::discoveryCacheKey($firewall).'.issuer_keysets');
        }

        return $key;
    }
}
