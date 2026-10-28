<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakBundle\Tests\Functional;

use Vinh0809it\KeycloakBundle\Test\KeycloakStub;
use Vinh0809it\KeycloakBundle\Tests\Functional\App\TestKernel;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\BrowserKit\Cookie;

/**
 * A booted firewall on keycloak.token_handler, against the stub realm: Symfony's real
 * `oidc` handler discovers the realm, fetches its keys and verifies the signature, `iss`, `aud` and
 * `exp` of tokens the stub signs.
 */
final class RealmFirewallTest extends WebTestCase
{
    private KernelBrowser $client;
    private KeycloakStub $members;
    private KeycloakStub $staff;

    protected static function getKernelClass(): string
    {
        return TestKernel::class;
    }

    protected function setUp(): void
    {
        $this->client = self::createClient();
        $this->members = self::getContainer()->get('test.realm.members');
        $this->staff = self::getContainer()->get('test.realm.staff');
        KeycloakStub::reset();
    }

    public function testASignedTokenIsTheDefaultResolversPrincipal(): void
    {
        $this->client->request('GET', '/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$this->token(['azp' => 'member-app'])]);

        self::assertResponseIsSuccessful();
        self::assertSame('{"user":"member:sub-1"}', $this->client->getResponse()->getContent());
        self::assertContains('/realms/members/.well-known/openid-configuration', array_column(KeycloakStub::$requests, '_path'), 'discovery resolves under the realm path, whatever its trailing slash');
    }

    public function testATokenIsRoutedByItsClient(): void
    {
        $this->client->request('GET', '/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$this->token(['azp' => 'staff-web'])]);

        self::assertSame('{"user":"staff:sub-1"}', $this->client->getResponse()->getContent());
    }

    public function testTheTokenCanRideInTheConfiguredCookie(): void
    {
        $this->client->getCookieJar()->set(new Cookie('access_token', $this->token(['azp' => 'member-app'])));
        $this->client->request('GET', '/whoami');

        self::assertSame('{"user":"member:sub-1"}', $this->client->getResponse()->getContent());
    }

    public function testTheBearerHeaderWinsOverTheCookieInTheOrderTheFirewallListsThem(): void
    {
        $this->client->getCookieJar()->set(new Cookie('access_token', $this->token(['azp' => 'staff-web'])));
        $this->client->request('GET', '/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$this->token(['azp' => 'member-app'])]);

        self::assertSame('{"user":"member:sub-1"}', $this->client->getResponse()->getContent());
    }

    public function testADevTokenAnswersWithItsClaimsThroughTheSameResolvers(): void
    {
        $this->client->request('GET', '/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer dev.staff']);

        self::assertSame('{"user":"staff:dev.staff"}', $this->client->getResponse()->getContent());
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function refusedClaims(): iterable
    {
        yield 'another audience' => [['aud' => 'someone-else']];
        yield 'an issuer no firewall realm is' => [['iss' => 'https://keycloak.test/realms/other']];
        yield 'expired' => [['iat' => time() - 600, 'exp' => time() - 300]];
    }

    /**
     * @param array<string, mixed> $claims
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('refusedClaims')]
    public function testATokenTheRealmDidNotIssueForThisServiceIsRefused(array $claims): void
    {
        $this->client->request('GET', '/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$this->token($claims)]);

        self::assertResponseStatusCodeSame(401);
    }

    public function testATamperedSignatureIsRefused(): void
    {
        [$header, , $signature] = explode('.', $this->token());
        $forged = rtrim(strtr(base64_encode((string) json_encode(['sub' => 'admin', 'aud' => 'api', 'iss' => TestKernel::MEMBERS, 'exp' => time() + 300])), '+/', '-_'), '=');

        $this->client->request('GET', '/whoami', server: ['HTTP_AUTHORIZATION' => "Bearer $header.$forged.$signature"]);

        self::assertResponseStatusCodeSame(401);
    }

    public function testNoTokenIsUnauthenticated(): void
    {
        $this->client->request('GET', '/whoami');

        self::assertResponseStatusCodeSame(401);
    }

    public function testAFirewallOverSeveralRealmsAcceptsEach(): void
    {
        $this->client->request('GET', '/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$this->staffToken(['azp' => 'staff-web'])]);
        self::assertSame('{"user":"staff:sub-1"}', $this->client->getResponse()->getContent());

        $this->client->request('GET', '/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$this->token(['azp' => 'member-app'])]);
        self::assertSame('{"user":"member:sub-1"}', $this->client->getResponse()->getContent());
    }

    public function testAFirewallRefusesARealmItDoesNotAccept(): void
    {
        $this->client->request('GET', '/members/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$this->staffToken()]);
        self::assertResponseStatusCodeSame(401);

        $this->client->request('GET', '/members/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$this->token()]);
        self::assertSame('{"user":"member:sub-1"}', $this->client->getResponse()->getContent());
    }

    /** One realm's key never vouches for another realm's issuer, even where both are accepted. */
    public function testATokenNamingOneRealmButSignedByAnotherIsRefused(): void
    {
        $this->client->request('GET', '/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$this->staffToken(['iss' => TestKernel::MEMBERS])]);

        self::assertResponseStatusCodeSame(401);
    }

    /** Another OpenID provider's token goes through the same authenticator, to that provider's resolver. */
    public function testAnotherIssuersTokenIsVerifiedHereAndResolvedByItsOwnResolver(): void
    {
        $this->client->request('GET', '/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$this->legacyToken()]);
        self::assertSame('{"user":"legacy:sub-1"}', $this->client->getResponse()->getContent());

        $this->client->request('GET', '/members/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$this->legacyToken()]);
        self::assertResponseStatusCodeSame(401, 'a firewall that does not list it refuses it');
    }

    /** Neither realm vouches for the other provider's issuer, nor it for theirs. */
    public function testATokenNamingTheOtherIssuerButSignedByARealmIsRefused(): void
    {
        $this->client->request('GET', '/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$this->token(['iss' => TestKernel::LEGACY])]);

        self::assertResponseStatusCodeSame(401);
    }

    /** A token the app issues itself, through a decorator of the firewall's token handler. */
    public function testTheAppsOwnTokenGoesThroughItsDecorator(): void
    {
        $this->client->request('GET', '/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer own-token']);
        self::assertSame('{"user":"own:own"}', $this->client->getResponse()->getContent());

        $this->client->request('GET', '/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$this->token(['azp' => 'member-app'])]);
        self::assertSame('{"user":"member:sub-1"}', $this->client->getResponse()->getContent(), 'and every other bearer still reaches the realms');
    }

    /** Any other bearer is the one authenticator's to refuse. */
    public function testAnUnknownBearerIsRefused(): void
    {
        $this->client->request('GET', '/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer opaque-token']);

        self::assertResponseStatusCodeSame(401);
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function token(array $claims = []): string
    {
        return $this->members->sign($claims + ['sub' => 'sub-1', 'aud' => 'api']);
    }

    private function legacyToken(): string
    {
        return self::getContainer()->get('test.realm.legacy')->sign(['sub' => 'sub-1', 'aud' => 'api']);
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function staffToken(array $claims = []): string
    {
        return $this->staff->sign($claims + ['sub' => 'sub-1', 'aud' => 'api']);
    }
}
