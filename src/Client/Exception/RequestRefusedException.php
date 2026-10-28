<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Client\Exception;

/**
 * Keycloak answered a 4xx: the request reached it and was refused. `error` is the OAuth error code
 * (`invalid_grant`...) when the body carried one, which an SPI endpoint may not.
 */
class RequestRefusedException extends \RuntimeException implements KeycloakException
{
    /**
     * @param array<mixed> $body the decoded response body, empty when it was not JSON
     */
    public function __construct(
        public readonly int $status,
        public readonly ?string $error,
        public readonly array $body = [],
    ) {
        $description = \is_string($body['error_description'] ?? null) ? ': '.$body['error_description'] : '';

        parent::__construct(\sprintf('Keycloak refused the request (%d %s)%s.', $status, $error ?? '', $description));
    }
}
