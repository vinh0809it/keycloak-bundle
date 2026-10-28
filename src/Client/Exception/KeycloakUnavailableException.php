<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Client\Exception;

/** Keycloak could not be reached, failed with a 5xx, or answered a success without what it owes. */
final class KeycloakUnavailableException extends \RuntimeException implements KeycloakException
{
}
