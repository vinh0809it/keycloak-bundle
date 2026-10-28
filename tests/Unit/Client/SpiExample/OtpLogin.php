<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Tests\Unit\Client\SpiExample;

use Vinh0809it\KeycloakBundle\Client\KeycloakClient;
use Vinh0809it\KeycloakBundle\Client\TokenSet;

/**
 * What code for a Keycloak SPI looks like beside the bundle, not in it: an OTP login made of a realm
 * resource that sends the code (`otp/send`) and a direct-grant authenticator that reads the code
 * from the token request. Both reach Keycloak through the client's two primitives.
 */
final readonly class OtpLogin
{
    public function __construct(private KeycloakClient $client)
    {
    }

    /** Sends a code to $username; the session id comes back with the login. */
    public function send(string $username): string
    {
        $body = $this->client->realm('POST', 'otp/send', ['json' => ['username' => $username]]);

        return (string) $body['session'];
    }

    public function login(string $username, string $session, string $code): TokenSet
    {
        return $this->client->password($username, '', ['session' => $session, 'otp' => $code]);
    }
}
