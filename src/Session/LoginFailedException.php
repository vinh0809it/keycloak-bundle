<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Session;

use Vinh0809it\KeycloakBundle\Client\Exception\KeycloakException;

/**
 * A browser's login that cannot be completed: none in progress (the cookie is missing, tampered with
 * or expired), a callback whose `state` or `iss` is not the login's own, a login the realm ended
 * with an OAuth `error` (`access_denied`, `login_required`...), or a code it refused
 * (`invalid_grant`). {@see $returnTo} is where the login meant to go, when its cookie was valid,
 * so the app can send the browser back there with the error. A return URL {@see BrowserLogin}
 * does not allow fails the same way, from start().
 */
final class LoginFailedException extends \RuntimeException implements KeycloakException
{
    public function __construct(
        string $message,
        public readonly ?string $error = null,
        public readonly ?string $returnTo = null,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }
}
