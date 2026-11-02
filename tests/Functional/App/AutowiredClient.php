<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Tests\Functional\App;

use Vinh0809it\KeycloakBundle\Client\KeycloakClient;
use Vinh0809it\KeycloakBundle\Session\BrowserLogin;
use Vinh0809it\KeycloakBundle\Session\SessionCookies;

/** An app service taking the bundle's services by autowiring alone. */
final readonly class AutowiredClient
{
    public function __construct(
        public KeycloakClient $webClient,
        public BrowserLogin $webLogin,
        public KeycloakClient $client,
        public SessionCookies $cookies,
    ) {
    }
}
