<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Client;

use Vinh0809it\KeycloakBundle\Client\Exception\InvalidClientException;
use Vinh0809it\KeycloakBundle\Client\Exception\KeycloakUnavailableException;
use Vinh0809it\KeycloakBundle\Client\Exception\RequestRefusedException;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as TransportException;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * One Keycloak client of one realm: the standard OpenID Connect endpoints on its behalf.
 *
 * The token endpoint authenticates the client with `client_secret_post` when a secret is set; a
 * public client sends its id alone.
 *
 * A Keycloak SPI is reached through two primitives rather than methods of its own, so code for an
 * SPI lives beside this client, not in it: {@see token()} takes any grant with the form fields an
 * SPI authenticator reads, and {@see realm()} calls an SPI's realm resource.
 *
 *     $client->token(['grant_type' => 'password', 'username' => $user, 'otp' => $otp]);
 *     $client->realm('POST', 'my-provider/send', ['json' => ['to' => $user]]);
 */
final readonly class KeycloakClient
{
    private string $realm;
    private string $publicRealm;

    /**
     * @param string      $realm       the realm URL this service reaches Keycloak at, e.g. http://keycloak:8080/realms/customers
     * @param string|null $publicRealm the realm URL a browser reaches, for {@see authorizationUrl()}; defaults to $realm
     */
    public function __construct(
        private HttpClientInterface $http,
        string $realm,
        public string $clientId,
        #[\SensitiveParameter]
        private ?string $clientSecret = null,
        ?string $publicRealm = null,
    ) {
        $this->realm = rtrim($realm, '/');
        $this->publicRealm = rtrim('' !== (string) $publicRealm ? (string) $publicRealm : $realm, '/');
    }

    /** The realm URL a browser reaches, which is also the `iss` its tokens and callbacks carry. */
    public function issuer(): string
    {
        return $this->publicRealm;
    }

    /**
     * Any grant at the token endpoint, with this client's credentials added.
     *
     * @param array<string, string> $grant `grant_type` and its fields
     *
     * @throws InvalidClientException       this client was refused
     * @throws RequestRefusedException      the grant was refused (`invalid_grant`...)
     * @throws KeycloakUnavailableException
     */
    public function token(array $grant): TokenSet
    {
        $body = $this->send('protocol/openid-connect/token', $grant);
        if (!\is_string($body['access_token'] ?? null) || '' === $body['access_token']) {
            throw new KeycloakUnavailableException('Keycloak answered the grant with no access token.');
        }

        return TokenSet::fromResponse($body);
    }

    /** A token for this client's own service account. */
    public function clientCredentials(): TokenSet
    {
        return $this->token(['grant_type' => 'client_credentials']);
    }

    /**
     * The direct grant. $extra carries what an SPI authenticator reads beside or instead of the
     * password.
     *
     * @param array<string, string> $extra
     */
    public function password(string $username, #[\SensitiveParameter] string $password, array $extra = []): TokenSet
    {
        return $this->token(['grant_type' => 'password', 'username' => $username, 'password' => $password] + $extra);
    }

    /**
     * Where a browser goes to sign in: the realm's own page, authorization code flow with PKCE (S256).
     *
     * @param array<string, string|null> $extra further parameters (`login_hint`, `prompt`, `kc_idp_hint`...) and the `scope`, `openid`
     *                                          by default; a null one is left out. The client, redirect URI, state, PKCE and response mode
     *                                          (the query) are the method's own
     */
    public function authorizationUrl(string $redirectUri, string $state, string $codeChallenge, array $extra = []): string
    {
        $extra += ['scope' => 'openid'];
        unset($extra['response_mode']);

        return $this->publicRealm.'/protocol/openid-connect/auth?'.http_build_query(array_filter([
            'client_id' => $this->clientId,
            'response_type' => 'code',
            'scope' => $extra['scope'],
            'redirect_uri' => $redirectUri,
            'state' => $state,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ] + $extra, static fn (?string $value): bool => null !== $value), '', '&', \PHP_QUERY_RFC3986);
    }

    /**
     * Where a browser goes to end its Keycloak SSO session (RP-initiated logout), then back to
     * $postLogoutRedirectUri, which must be one of the client's valid post-logout redirect URIs.
     * With the session's ID token as $idTokenHint Keycloak logs out without asking; without it,
     * it asks the user to confirm. {@see logout()} ends one refresh token's session from the server
     * instead, and leaves the browser's SSO cookie in place.
     */
    public function logoutUrl(string $postLogoutRedirectUri, ?string $idTokenHint = null, ?string $state = null): string
    {
        return $this->publicRealm.'/protocol/openid-connect/logout?'.http_build_query(array_filter([
            'client_id' => $this->clientId,
            'post_logout_redirect_uri' => $postLogoutRedirectUri,
            'id_token_hint' => $idTokenHint,
            'state' => $state,
        ], static fn (?string $value): bool => null !== $value), '', '&', \PHP_QUERY_RFC3986);
    }

    public function exchangeCode(string $code, string $redirectUri, string $codeVerifier): TokenSet
    {
        return $this->token([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'code_verifier' => $codeVerifier,
        ]);
    }

    public function refresh(#[\SensitiveParameter] string $refreshToken): TokenSet
    {
        return $this->token(['grant_type' => 'refresh_token', 'refresh_token' => $refreshToken]);
    }

    /** Ends the Keycloak session behind the refresh token. */
    public function logout(#[\SensitiveParameter] string $refreshToken): void
    {
        $this->send('protocol/openid-connect/logout', ['refresh_token' => $refreshToken]);
    }

    /** Revokes one token (RFC 7009); a refresh token's revocation ends its session's offline access. */
    public function revoke(#[\SensitiveParameter] string $token, string $hint = 'refresh_token'): void
    {
        $this->send('protocol/openid-connect/revoke', ['token' => $token, 'token_type_hint' => $hint]);
    }

    /**
     * The claims of the user an access token was issued to, from the realm's userinfo endpoint.
     * The token must carry the `openid` scope (403 otherwise); one Keycloak no longer accepts
     * (expired, its session ended) is refused with a 401.
     *
     * @return array<mixed>
     *
     * @throws RequestRefusedException
     * @throws KeycloakUnavailableException
     */
    public function userinfo(#[\SensitiveParameter] string $accessToken): array
    {
        return $this->request('GET', $this->realm.'/protocol/openid-connect/userinfo', ['auth_bearer' => $accessToken]);
    }

    /**
     * A request to the realm's own resources, relative to the realm URL: what an SPI's
     * `RealmResourceProvider` serves under `/realms/{realm}/{provider-id}/...`. $options are the
     * HTTP client's (`json`, `body`, `query`, `headers`...); the client's credentials are not added.
     *
     * @param array<string, mixed> $options
     *
     * @return array<mixed> the decoded JSON body, empty when there was none
     *
     * @throws RequestRefusedException      a 4xx
     * @throws KeycloakUnavailableException
     */
    public function realm(string $method, string $path, array $options = []): array
    {
        return $this->request($method, $this->realm.'/'.ltrim($path, '/'), $options);
    }

    /**
     * @param array<string, string> $form
     *
     * @return array<mixed>
     */
    private function send(string $endpoint, array $form): array
    {
        $form += ['client_id' => $this->clientId];
        if (null !== $this->clientSecret && '' !== $this->clientSecret) {
            $form += ['client_secret' => $this->clientSecret];
        }

        try {
            return $this->request('POST', $this->realm.'/'.$endpoint, ['body' => $form]);
        } catch (RequestRefusedException $e) {
            if (\in_array($e->error, ['invalid_client', 'unauthorized_client'], true)) {
                throw new InvalidClientException($e->status, $e->error, $e->body);
            }

            throw $e;
        }
    }

    /**
     * @param array<string, mixed> $options
     *
     * @return array<mixed>
     */
    private function request(string $method, string $url, array $options): array
    {
        try {
            $response = $this->http->request($method, $url, $options);
            $status = $response->getStatusCode();
            $content = $response->getContent(false);
        } catch (TransportException $e) {
            throw new KeycloakUnavailableException('Keycloak is unreachable.', 0, $e);
        }

        $body = json_decode($content, true);
        $body = \is_array($body) ? $body : [];

        if ($status >= 500) {
            throw new KeycloakUnavailableException(\sprintf('Keycloak failed with %d.', $status));
        }
        if ($status >= 400) {
            throw new RequestRefusedException($status, \is_string($body['error'] ?? null) ? $body['error'] : null, $body);
        }

        return $body;
    }
}
