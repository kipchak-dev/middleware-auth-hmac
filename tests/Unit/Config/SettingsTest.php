<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Tests\Unit\Config;

use Kipchak\Middleware\Auth\HMAC\Config\Algorithm;
use Kipchak\Middleware\Auth\HMAC\Config\Profile;
use Kipchak\Middleware\Auth\HMAC\Config\ReplayStore;
use Kipchak\Middleware\Auth\HMAC\Config\Scheme;
use Kipchak\Middleware\Auth\HMAC\Config\Settings;
use Kipchak\Middleware\Auth\HMAC\Exceptions\InvalidConfiguration;
use Kipchak\Middleware\Auth\HMAC\Tests\Unit\Support\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SettingsTest extends TestCase
{
    public function testDefaults(): void
    {
        $settings = Settings::fromArray([
            'profiles' => ['api' => ['keys' => ['client-a' => Fixtures::KIPCHAK_SECRET]]],
        ]);
        $profile = $settings->profile('api');

        $this->assertFalse($settings->enabled);
        $this->assertTrue($settings->ignoreOptions);
        $this->assertSame([], $settings->ignorePaths);
        $this->assertNull($settings->defaultProfile);

        $this->assertSame(Scheme::Kipchak, $profile->scheme);
        $this->assertSame('Kipchak-Signature', $profile->header);
        $this->assertSame(Algorithm::Sha256, $profile->algorithm);
        $this->assertSame(['client-a' => [Fixtures::KIPCHAK_SECRET]], $profile->keys);
        $this->assertSame(300, $profile->tolerance);
        $this->assertSame([], $profile->signedHeaders);
        $this->assertTrue($profile->requireNonce);
        $this->assertSame(1048576, $profile->maxBodyBytes);
        $this->assertTrue($profile->replay);

        $this->assertTrue($settings->replay->enabled);
        $this->assertSame(ReplayStore::Valkey, $settings->replay->store);
        $this->assertSame('cache', $settings->replay->pool);
        $this->assertSame('kipchak.hmac', $settings->replay->prefix);
        $this->assertFalse($settings->replay->failOpen);
    }

    public function testSchemeDefaultHeaders(): void
    {
        $settings = Settings::fromArray(Fixtures::config());

        $this->assertSame('Stripe-Signature', $settings->profile('stripe')->header);
        $this->assertSame('webhook', $settings->profile('standard')->header);
    }

    public function testStandardWebhooksSecretsAreDecoded(): void
    {
        $profile = Settings::fromArray(Fixtures::config())->profile('standard');

        $this->assertSame(base64_decode('MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw'), $profile->secrets[0]);
    }

    public function testSignedHeadersAreLowerCasedAndDeduplicated(): void
    {
        $profile = Profile::fromArray('api', [
            'keys' => ['client-a' => Fixtures::KIPCHAK_SECRET],
            'signed_headers' => ['Content-Type', 'content-type', 'X-Tenant'],
        ]);

        $this->assertSame(['content-type', 'x-tenant'], $profile->signedHeaders);
    }

    public function testNumericStringsFromEnvAreAccepted(): void
    {
        $profile = Profile::fromArray('api', [
            'keys' => ['client-a' => Fixtures::KIPCHAK_SECRET],
            'tolerance' => '60',
        ]);

        $this->assertSame(60, $profile->tolerance);
    }

    public function testProfileForPathPrefersPathMatchesThenDefault(): void
    {
        $settings = Settings::fromArray(Fixtures::config());

        $this->assertSame('stripe', $settings->profileForPath('/webhooks/stripe')->name);
        $this->assertSame('stripe', $settings->profileForPath('/webhooks/stripe/events')->name);
        $this->assertSame('standard', $settings->profileForPath('/webhooks/standard')->name);
        // Segment boundary: "/webhooks/stripey" is not under "/webhooks/stripe".
        $this->assertSame('api', $settings->profileForPath('/webhooks/stripey')->name);
        $this->assertSame('api', $settings->profileForPath('/v1/orders')->name);
    }

    public function testNoDefaultProfileLeavesUnmatchedPathsUnprotected(): void
    {
        $config = Fixtures::config();
        unset($config['default_profile']);
        $settings = Settings::fromArray($config);

        $this->assertNull($settings->profileForPath('/v1/orders'));
        $this->assertSame('stripe', $settings->profileForPath('/webhooks/stripe')->name);
    }

    public function testRootPathMatchesEverything(): void
    {
        $profile = Profile::fromArray('all', ['keys' => ['k' => Fixtures::KIPCHAK_SECRET], 'paths' => ['/']]);

        $this->assertTrue($profile->matchesPath('/'));
        $this->assertTrue($profile->matchesPath('/anything/at/all'));
    }

    public function testReplayCanBeTurnedOffGloballyOrPerProfile(): void
    {
        $settings = Settings::fromArray(Fixtures::config(['profiles' => ['stripe' => ['replay' => false]]]));
        $this->assertTrue($settings->replayEnabledFor($settings->profile('api')));
        $this->assertFalse($settings->replayEnabledFor($settings->profile('stripe')));

        $settings = Settings::fromArray(Fixtures::config(['replay' => ['enabled' => false]]));
        $this->assertFalse($settings->replayEnabledFor($settings->profile('api')));
    }

    /**
     * Kipchak loads its env() helper during Api::boot(); config files read outside a booted API need it loaded.
     */
    private static function loadKipchakFunctions(): void
    {
        require_once dirname((string) (new \ReflectionClass(\Kipchak\Core\Api::class))->getFileName()) . '/Functions.php';
    }

    public function testSampleConfigIsValid(): void
    {
        self::loadKipchakFunctions();
        putenv('HMAC_BILLING_SERVICE_SECRET=' . Fixtures::KIPCHAK_SECRET);
        putenv('STRIPE_WEBHOOK_SECRET=' . Fixtures::STRIPE_SECRET);
        putenv('WEBHOOK_SECRET=' . Fixtures::STANDARD_WEBHOOKS_SECRET);

        try {
            $settings = Settings::fromArray(require __DIR__ . '/../../../sample.config.php');
        } finally {
            putenv('HMAC_BILLING_SERVICE_SECRET');
            putenv('STRIPE_WEBHOOK_SECRET');
            putenv('WEBHOOK_SECRET');
        }

        $this->assertSame(['api', 'stripe', 'standard'], array_keys($settings->profiles));
        $this->assertSame('stripe', $settings->profileForPath('/webhooks/stripe')->name);
        $this->assertSame(ReplayStore::Valkey, $settings->replay->store);
    }

    public function testSampleConfigRefusesToBootWithoutSecrets(): void
    {
        self::loadKipchakFunctions();
        $this->expectException(InvalidConfiguration::class);

        Settings::fromArray(require __DIR__ . '/../../../sample.config.php');
    }

    public function testUnknownProfileNameIsAConfigurationError(): void
    {
        $this->expectException(InvalidConfiguration::class);
        $this->expectExceptionMessage("no profile named 'nope'");

        Settings::fromArray(Fixtures::config())->profile('nope');
    }

    #[DataProvider('invalidConfigs')]
    public function testInvalidConfigurationFailsAtBoot(array $config, string $message): void
    {
        $this->expectException(InvalidConfiguration::class);
        $this->expectExceptionMessage($message);

        Settings::fromArray($config);
    }

    public static function invalidConfigs(): iterable
    {
        $key = ['client-a' => Fixtures::KIPCHAK_SECRET];
        $profile = static fn (array $profile, array $rest = []): array => ['profiles' => ['p' => $profile]] + $rest;

        yield 'no profiles' => [[], 'at least one profile'];
        yield 'unknown default profile' => [$profile(['keys' => $key], ['default_profile' => 'x']), "names 'x'"];
        yield 'unknown scheme' => [$profile(['scheme' => 'aws-sigv4', 'keys' => $key]), 'scheme must be one of'];
        yield 'unknown algorithm' => [$profile(['algorithm' => 'md5', 'keys' => $key]), 'algorithm must be one of'];
        yield 'algorithm on stripe' => [$profile(['scheme' => 'stripe', 'algorithm' => 'sha512', 'secrets' => ['x']]), 'fixed at sha256'];
        yield 'kipchak without keys' => [$profile([]), 'at least one key ID'];
        yield 'short secret' => [$profile(['keys' => ['client-a' => 'short']]), 'at least 16 bytes'];
        yield 'empty secret list' => [$profile(['keys' => ['client-a' => []]]), 'at least one secret'];
        yield 'bad key id' => [$profile(['keys' => ['client a' => Fixtures::KIPCHAK_SECRET]]), 'invalid key ID'];
        yield 'stripe without secrets' => [$profile(['scheme' => 'stripe']), 'at least one secret'];
        yield 'stripe empty secret' => [$profile(['scheme' => 'stripe', 'secrets' => ['']]), 'non-empty string'];
        yield 'standard webhooks bad base64' => [$profile(['scheme' => 'standard-webhooks', 'secrets' => ['whsec_***not base64***']]), 'must be base64'];
        yield 'bad header name' => [$profile(['keys' => $key, 'header' => 'Bad Header']), 'valid HTTP header name'];
        yield 'bad signed header' => [$profile(['keys' => $key, 'signed_headers' => ['ok', 'not ok']]), 'valid HTTP header names'];
        yield 'relative path' => [$profile(['keys' => $key, 'paths' => ['webhooks']]), "start with '/'"];
        yield 'zero tolerance' => [$profile(['keys' => $key, 'tolerance' => 0]), 'positive integer'];
        yield 'negative body limit' => [$profile(['keys' => $key, 'max_body_bytes' => -1]), 'positive integer'];
        yield 'unknown store' => [$profile(['keys' => $key], ['replay' => ['store' => 'mysql']]), 'replay.store must be one of'];
        yield 'container store without service' => [$profile(['keys' => $key], ['replay' => ['store' => 'container']]), 'must name a container service'];
        yield 'prefix with reserved characters' => [$profile(['keys' => $key], ['replay' => ['prefix' => 'hmac:nonces']]), 'replay.prefix'];
    }
}
