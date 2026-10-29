<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Test;

use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * Several stub realms, or other OpenID providers, behind one `mock_response_factory`: each request
 * goes to the stub whose issuer URL it is under, the longest one when issuers nest, and gets a 404
 * when it is under none. Each stub's issuer must be the URL the app reaches it at.
 */
final readonly class KeycloakStubRouter
{
    /** @var list<KeycloakStub> */
    private array $realms;

    public function __construct(KeycloakStub ...$realms)
    {
        $realms = array_values($realms);
        usort($realms, static fn (KeycloakStub $a, KeycloakStub $b): int => \strlen($b->issuer()) <=> \strlen($a->issuer()));
        $this->realms = $realms;
    }

    /**
     * @param array<string, mixed> $options
     */
    public function __invoke(string $method, string $url, array $options): MockResponse
    {
        foreach ($this->realms as $realm) {
            if ($url === $realm->issuer() || str_starts_with($url, $realm->issuer().'/')) {
                return $realm($method, $url, $options);
            }
        }

        return new MockResponse('', ['http_code' => 404]);
    }
}
