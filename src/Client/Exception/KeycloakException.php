<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Client\Exception;

/**
 * Anything the client throws. Catch the subclasses to tell who is at fault:
 *
 *  - {@see KeycloakUnavailableException}: Keycloak could not be reached or failed (5xx), retryable;
 *  - {@see InvalidClientException}: this service's client is misconfigured (a wrong secret, a
 *    client without a service account), never the end user's doing and never worth retrying;
 *  - {@see RequestRefusedException}: Keycloak refused what was asked (a spent code, an expired
 *    refresh token, wrong credentials), usually the end user signs in again.
 */
interface KeycloakException extends \Throwable
{
}
