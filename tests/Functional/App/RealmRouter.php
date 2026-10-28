<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Tests\Functional\App;

use Vinh0809it\KeycloakBundle\Test\KeycloakStub;
use Symfony\Component\HttpClient\Response\MockResponse;

/** The test kernel's HTTP clients answer from the provider whose URL a request is under. */
final readonly class RealmRouter
{
    public function __construct(private KeycloakStub $members, private KeycloakStub $staff, private KeycloakStub $legacy)
    {
    }

    /**
     * @param array<string, mixed> $options
     */
    public function __invoke(string $method, string $url, array $options): MockResponse
    {
        $realm = match (true) {
            str_contains($url, '/realms/staff') => $this->staff,
            str_starts_with($url, TestKernel::LEGACY) => $this->legacy,
            default => $this->members,
        };

        return $realm($method, $url, $options);
    }
}
