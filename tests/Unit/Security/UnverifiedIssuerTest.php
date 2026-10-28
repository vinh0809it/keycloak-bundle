<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Tests\Unit\Security;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Vinh0809it\KeycloakBundle\Security\UnverifiedIssuer;

final class UnverifiedIssuerTest extends TestCase
{
    public function testReadsTheIssuerOfAnUnpaddedBase64UrlPayload(): void
    {
        $payload = self::base64Url(['iss' => 'https://idp.test/a', 'name' => '>>>???']);
        self::assertNotSame(0, \strlen($payload) % 4, 'the payload needs padding');
        self::assertMatchesRegularExpression('/[-_]/', $payload, 'the payload uses the URL-safe alphabet');

        self::assertSame('https://idp.test/a', UnverifiedIssuer::of('h.'.$payload.'.s'));
    }

    public function testStripsATrailingSlash(): void
    {
        self::assertSame('https://idp.test', UnverifiedIssuer::of('h.'.self::base64Url(['iss' => 'https://idp.test/']).'.s'));
    }

    /** @return iterable<string, array{string}> */
    public static function notAnIssuer(): iterable
    {
        yield 'no iss claim' => ['h.'.self::base64Url(['sub' => 'u1']).'.s'];
        yield 'a non-string iss' => ['h.'.self::base64Url(['iss' => 42]).'.s'];
        yield 'not a JWT' => ['opaque-token'];
        yield 'an empty payload' => ['h..s'];
        yield 'a payload that is not base64' => ['h.!!!.s'];
        yield 'base64 that is not JSON' => ['h.'.rtrim(base64_encode('not json'), '=').'.s'];
        yield 'JSON that is not an object' => ['h.'.rtrim(base64_encode('"iss"'), '=').'.s'];
    }

    #[DataProvider('notAnIssuer')]
    public function testIsNullWhenTheTokenClaimsNoIssuer(string $token): void
    {
        self::assertNull(UnverifiedIssuer::of($token));
    }

    /** @param array<string, mixed> $claims */
    private static function base64Url(array $claims): string
    {
        return rtrim(strtr(base64_encode((string) json_encode($claims, \JSON_UNESCAPED_SLASHES)), '+/', '-_'), '=');
    }
}
