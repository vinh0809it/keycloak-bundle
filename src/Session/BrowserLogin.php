<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Session;

use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Vinh0809it\KeycloakBundle\Client\Exception\InvalidClientException;
use Vinh0809it\KeycloakBundle\Client\Exception\KeycloakException;
use Vinh0809it\KeycloakBundle\Client\Exception\KeycloakUnavailableException;
use Vinh0809it\KeycloakBundle\Client\Exception\RequestRefusedException;
use Vinh0809it\KeycloakBundle\Client\KeycloakClient;

/**
 * A browser's sign-in at the realm, authorization code flow with PKCE, for one client.
 *
 * {@see start()} draws a random `state` and PKCE verifier, keeps them with the redirect URI and the
 * page to return to in a short-lived login cookie, and redirects to the realm's login page.
 * {@see finish()}, on the callback, checks the cookie's signature and age, the `state` the realm
 * sent back and its `iss` (RFC 9207) when present, then exchanges the code with the kept verifier.
 * A callback it refuses has its code spent, so nobody else can redeem it.
 *
 * The page to return to is a path of this app (`/orders`), or a URL on one of the allowed return
 * origins (`https://web.example.com`, or `https://*.example.com` for its subdomains); anything
 * else is refused at start(), so the one finish() hands back is safe to redirect to.
 *
 * The login cookie is HttpOnly, Secure and SameSite=Lax (the callback is a top-level navigation
 * from the realm), signed with the app's secret, and lives {@see LIFETIME} seconds. One browser
 * holds one login at a time: a second one started meanwhile replaces it.
 */
final readonly class BrowserLogin
{
    public const LIFETIME = 600;

    /**
     * @param list<string>         $returnOrigins `scheme://host[:port]`, or `scheme://*.domain` for its subdomains, that absolute return URLs may be on
     * @param \Closure(): int|null $clock         the current Unix time; time() when null
     */
    public function __construct(
        private KeycloakClient $client,
        private CookieOptions $cookie,
        #[\SensitiveParameter]
        private string $secret,
        private array $returnOrigins = [],
        private ?\Closure $clock = null,
    ) {
    }

    /**
     * The redirect to the realm's login page, with the login cookie set on it.
     *
     * @param string                     $redirectUri the callback, one of the client's valid redirect URIs
     * @param string|null                $returnTo    where to send the browser once signed in: a path of this app, or a URL on an allowed return origin
     * @param array<string, string|null> $extra       further authorization parameters (`scope`, `login_hint`, `kc_idp_hint`...)
     *
     * @throws LoginFailedException a return URL that is not allowed
     */
    public function start(string $redirectUri, ?string $returnTo = null, array $extra = []): RedirectResponse
    {
        if (null !== $returnTo && !$this->allowsReturnTo($returnTo)) {
            throw new LoginFailedException(\sprintf('"%s" is neither a path of this app nor on an allowed return origin.', $returnTo), 'invalid_return_to');
        }

        $state = self::random(32);
        $verifier = self::random(48);
        $challenge = self::base64Url(hash('sha256', $verifier, true));

        $response = new RedirectResponse($this->client->authorizationUrl($redirectUri, $state, $challenge, $extra));
        $payload = self::base64Url((string) json_encode([
            'state' => $state,
            'verifier' => $verifier,
            'redirect_uri' => $redirectUri,
            'return_to' => $returnTo,
            'expires' => $this->now() + self::LIFETIME,
        ], \JSON_THROW_ON_ERROR));
        $response->headers->setCookie(Cookie::create(
            $this->cookie->name,
            $payload.'.'.$this->sign($payload),
            $this->now() + self::LIFETIME,
            $this->cookie->path,
            $this->cookie->domain,
            true,
            true,
            false,
            Cookie::SAMESITE_LAX,
        ));

        return $response;
    }

    /**
     * The tokens of the login the callback request completes. Clear the login cookie on the
     * response with {@see clearLoginCookie()}, whatever the outcome.
     *
     * @throws LoginFailedException         no login of this browser to complete, a `state` or `iss` that is not its own, the realm ended the
     *                                      login or refused its code
     * @throws InvalidClientException       this service's client was refused
     * @throws KeycloakUnavailableException
     */
    public function finish(Request $request): CompletedLogin
    {
        try {
            $login = $this->login($request);
        } catch (LoginFailedException $e) {
            $this->spend($request, null);

            throw $e;
        }
        $fail = function (string $message, ?string $error = null) use ($request, $login): LoginFailedException {
            $this->spend($request, $login['redirect_uri']);

            return new LoginFailedException($message, $error, $login['return_to']);
        };

        $state = $request->query->get('state');
        if (!\is_string($state) || !hash_equals($login['state'], $state)) {
            throw $fail('The callback\'s state is not the one this browser\'s login started with.');
        }
        $issuer = $request->query->get('iss');
        if (null !== $issuer && $issuer !== $this->client->issuer()) {
            throw $fail(\sprintf('The callback comes from issuer "%s", not this client\'s realm.', $issuer));
        }
        $error = $request->query->get('error');
        if (null !== $error) {
            $description = (string) $request->query->get('error_description');
            throw $fail(\sprintf('The realm ended the login: %s.', '' !== $description ? $description : $error), $error);
        }
        $code = $request->query->get('code');
        if (!\is_string($code) || '' === $code) {
            throw $fail('The callback carries no code.');
        }

        try {
            $tokens = $this->client->exchangeCode($code, $login['redirect_uri'], $login['verifier']);
        } catch (InvalidClientException $e) {
            throw $e;
        } catch (RequestRefusedException $e) {
            throw new LoginFailedException('The realm refused the login\'s code.', $e->error, $login['return_to'], $e);
        }

        return new CompletedLogin($tokens, $login['return_to']);
    }

    /**
     * Redeems the code of a callback this login refuses with a verifier nobody holds: Keycloak
     * invalidates a code on a failed exchange, so whoever started the login the code belongs to
     * cannot redeem it afterwards. Best effort.
     */
    private function spend(Request $request, ?string $redirectUri): void
    {
        $code = $request->query->get('code');
        if (!\is_string($code) || '' === $code) {
            return;
        }

        try {
            $this->client->exchangeCode($code, $redirectUri ?? $request->getSchemeAndHttpHost().$request->getPathInfo(), self::random(48));
        } catch (KeycloakException) {
        }
    }

    /** Clears the login cookie on $response. */
    public function clearLoginCookie(Response $response): void
    {
        $response->headers->clearCookie($this->cookie->name, $this->cookie->path, $this->cookie->domain, true, true, Cookie::SAMESITE_LAX);
    }

    /**
     * @return array{state: string, verifier: string, redirect_uri: string, return_to: ?string}
     */
    private function login(Request $request): array
    {
        $value = $request->cookies->get($this->cookie->name);
        [$payload, $signature] = \is_string($value) ? explode('.', $value, 2) + [1 => ''] : ['', ''];
        if ('' === $payload || !hash_equals($this->sign($payload), $signature)) {
            throw new LoginFailedException('This browser has no login in progress.');
        }

        $login = json_decode((string) base64_decode(strtr($payload, '-_', '+/'), true), true);
        if (!\is_array($login) || !\is_int($login['expires'] ?? null) || $login['expires'] < $this->now()) {
            throw new LoginFailedException('This browser\'s login has expired.');
        }

        /* @var array{state: string, verifier: string, redirect_uri: string, return_to: ?string} $login */
        return $login;
    }

    private function allowsReturnTo(string $url): bool
    {
        if (str_starts_with($url, '/')) {
            return !str_starts_with($url, '//') && !str_contains($url, '\\');
        }

        $parts = parse_url($url);
        if (false === $parts || !\in_array($parts['scheme'] ?? null, ['http', 'https'], true) || !isset($parts['host']) || isset($parts['user']) || isset($parts['pass'])) {
            return false;
        }
        $scheme = $parts['scheme'].'://';
        $host = strtolower($parts['host']).(isset($parts['port']) ? ':'.$parts['port'] : '');

        foreach ($this->returnOrigins as $origin) {
            $origin = strtolower(rtrim($origin, '/'));
            if ($origin === $scheme.$host) {
                return true;
            }
            if (str_starts_with($origin, $scheme.'*.') && str_ends_with($host, substr($origin, \strlen($scheme) + 1))) {
                return true;
            }
        }

        return false;
    }

    private function sign(string $payload): string
    {
        return self::base64Url(hash_hmac('sha256', $this->cookie->name.'|'.$payload, $this->secret, true));
    }

    private function now(): int
    {
        return null !== $this->clock ? ($this->clock)() : time();
    }

    private static function random(int $bytes): string
    {
        return self::base64Url(random_bytes($bytes));
    }

    private static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
