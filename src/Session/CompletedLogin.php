<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Session;

use Vinh0809it\KeycloakBundle\Client\TokenSet;

/** A browser's login the callback completed: its tokens, and where the app meant to send it next. */
final readonly class CompletedLogin
{
    public function __construct(
        public TokenSet $tokens,
        public ?string $returnTo,
    ) {
    }
}
