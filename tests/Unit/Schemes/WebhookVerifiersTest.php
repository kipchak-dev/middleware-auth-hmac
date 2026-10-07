<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Tests\Unit\Schemes;

use Kipchak\Middleware\Auth\HMAC\Config\Profile;
use Kipchak\Middleware\Auth\HMAC\Exceptions\Failure;
use Kipchak\Middleware\Auth\HMAC\Exceptions\SignatureException;
use Kipchak\Middleware\Auth\HMAC\Schemes\StandardWebhooksVerifier;
use Kipchak\Middleware\Auth\HMAC\Schemes\StripeVerifier;
use Kipchak\Middleware\Auth\HMAC\Tests\Unit\Support\Fixtures;
use Kipchak\Middleware\Auth\HMAC\Tests\Unit\Support\Requests;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class WebhookVerifiersTest extends TestCase
{
    use Requests;

    private function assertFailure(Failure $expected, callable $callback): void
    {
        try {
            $callback();
            $this->fail("Expected {$expected->value}");
        } catch (SignatureException $exception) {
            $this->assertSame($expected, $exception->failure, $exception->getMessage());
        }
    }

    // --- Stripe -----------------------------------------------------------------------------------------------

    private function stripeProfile(array $secrets = [Fixtures::STRIPE_SECRET]): Profile
    {
        return Profile::fromArray('stripe', ['scheme' => 'stripe', 'secrets' => $secrets]);
    }

    private function stripe(string $header, string $body = Fixtures::STRIPE_BODY, int $now = Fixtures::NOW, ?Profile $profile = null): \Kipchak\Middleware\Auth\HMAC\Schemes\VerifiedSignature
    {
        $request = $this->request('POST', 'https://api.example.com/webhooks/stripe', ['Stripe-Signature' => $header], $body);

        return (new StripeVerifier())->verify($request, $body, $profile ?? $this->stripeProfile(), $now);
    }

    public function testStripeAcceptsTheIndependentlyComputedVector(): void
    {
        $verified = $this->stripe('t=' . Fixtures::NOW . ',v1=' . Fixtures::STRIPE_SIGNATURE);

        $this->assertSame(Fixtures::NOW, $verified->timestamp);
        $this->assertSame(Fixtures::STRIPE_SIGNATURE, $verified->replayId);
    }

    public function testStripeIgnoresV0AndUnknownSchemesAndAcceptsAnyV1(): void
    {
        $header = 't=' . Fixtures::NOW . ',v0=' . str_repeat('1', 64) . ',v1=' . str_repeat('2', 64) . ',v1=' . Fixtures::STRIPE_SIGNATURE . ',v9=future';

        $this->assertSame(Fixtures::STRIPE_SIGNATURE, $this->stripe($header)->replayId);
    }

    public function testStripeSecretRotation(): void
    {
        $profile = $this->stripeProfile(['whsec_new_secret_after_rolling', Fixtures::STRIPE_SECRET]);

        $this->assertSame(Fixtures::NOW, $this->stripe('t=' . Fixtures::NOW . ',v1=' . Fixtures::STRIPE_SIGNATURE, profile: $profile)->timestamp);
    }

    public function testStripeRejectsAChangedBody(): void
    {
        $this->assertFailure(Failure::Invalid, fn () => $this->stripe('t=' . Fixtures::NOW . ',v1=' . Fixtures::STRIPE_SIGNATURE, '{"id":"evt_other","object":"event"}'));
    }

    public function testStripeRejectsAChangedTimestamp(): void
    {
        $this->assertFailure(Failure::Invalid, fn () => $this->stripe('t=' . (Fixtures::NOW + 1) . ',v1=' . Fixtures::STRIPE_SIGNATURE, now: Fixtures::NOW + 1));
    }

    public function testStripeRejectsOldEvents(): void
    {
        $this->assertFailure(Failure::TimestampOutOfTolerance, fn () => $this->stripe('t=' . Fixtures::NOW . ',v1=' . Fixtures::STRIPE_SIGNATURE, now: Fixtures::NOW + 301));
    }

    #[DataProvider('malformedStripeHeaders')]
    public function testStripeMalformedHeaders(string $header): void
    {
        $this->assertFailure(Failure::Malformed, fn () => $this->stripe($header));
    }

    public static function malformedStripeHeaders(): iterable
    {
        yield 'no timestamp' => ['v1=' . Fixtures::STRIPE_SIGNATURE];
        yield 'two timestamps' => ['t=1,t=' . Fixtures::NOW . ',v1=' . Fixtures::STRIPE_SIGNATURE];
        yield 'only v0' => ['t=' . Fixtures::NOW . ',v0=' . Fixtures::STRIPE_SIGNATURE];
    }

    public function testStripeMissingHeader(): void
    {
        $request = $this->request('POST', 'https://api.example.com/webhooks/stripe', [], Fixtures::STRIPE_BODY);

        $this->assertFailure(Failure::Missing, fn () => (new StripeVerifier())->verify($request, Fixtures::STRIPE_BODY, $this->stripeProfile(), Fixtures::NOW));
    }

    // --- Standard Webhooks -------------------------------------------------------------------------------------

    private function standardProfile(array $overrides = []): Profile
    {
        return Profile::fromArray('standard', $overrides + ['scheme' => 'standard-webhooks', 'secrets' => [Fixtures::STANDARD_WEBHOOKS_SECRET]]);
    }

    private function standard(
        array $headers = [],
        string $body = Fixtures::STANDARD_WEBHOOKS_BODY,
        int $now = Fixtures::STANDARD_WEBHOOKS_TIMESTAMP,
        ?Profile $profile = null,
    ): \Kipchak\Middleware\Auth\HMAC\Schemes\VerifiedSignature {
        $headers = array_filter($headers + [
            'webhook-id' => Fixtures::STANDARD_WEBHOOKS_ID,
            'webhook-timestamp' => (string) Fixtures::STANDARD_WEBHOOKS_TIMESTAMP,
            'webhook-signature' => Fixtures::STANDARD_WEBHOOKS_SIGNATURE,
        ], static fn (?string $value): bool => $value !== null);
        $request = $this->request('POST', 'https://api.example.com/webhooks/standard', $headers, $body);

        return (new StandardWebhooksVerifier())->verify($request, $body, $profile ?? $this->standardProfile(), $now);
    }

    public function testStandardWebhooksAcceptsTheSpecVector(): void
    {
        $verified = $this->standard();

        $this->assertSame(Fixtures::STANDARD_WEBHOOKS_ID, $verified->messageId);
        $this->assertSame(Fixtures::STANDARD_WEBHOOKS_TIMESTAMP, $verified->timestamp);
        $this->assertSame(Fixtures::STANDARD_WEBHOOKS_ID . "\n" . Fixtures::STANDARD_WEBHOOKS_TIMESTAMP, $verified->replayId);
    }

    public function testStandardWebhooksAcceptsAnyOfSeveralSignaturesAndIgnoresV1a(): void
    {
        $verified = $this->standard(['webhook-signature' => 'v1a,c29tZXRoaW5n v1,bm9wZQ== ' . Fixtures::STANDARD_WEBHOOKS_SIGNATURE]);

        $this->assertSame(Fixtures::STANDARD_WEBHOOKS_ID, $verified->messageId);
    }

    public function testStandardWebhooksSecretWithoutPrefix(): void
    {
        $profile = $this->standardProfile(['secrets' => ['MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw']]);

        $this->assertSame(Fixtures::STANDARD_WEBHOOKS_ID, $this->standard(profile: $profile)->messageId);
    }

    public function testSvixHeaderPrefix(): void
    {
        $request = $this->request('POST', 'https://api.example.com/webhooks/svix', [
            'svix-id' => Fixtures::STANDARD_WEBHOOKS_ID,
            'svix-timestamp' => (string) Fixtures::STANDARD_WEBHOOKS_TIMESTAMP,
            'svix-signature' => Fixtures::STANDARD_WEBHOOKS_SIGNATURE,
        ], Fixtures::STANDARD_WEBHOOKS_BODY);

        $verified = (new StandardWebhooksVerifier())->verify(
            $request,
            Fixtures::STANDARD_WEBHOOKS_BODY,
            $this->standardProfile(['header_prefix' => 'svix']),
            Fixtures::STANDARD_WEBHOOKS_TIMESTAMP
        );

        $this->assertSame(Fixtures::STANDARD_WEBHOOKS_ID, $verified->messageId);
    }

    #[DataProvider('tamperedStandardWebhooks')]
    public function testStandardWebhooksRejectsTampering(array $headers, string $body): void
    {
        $this->assertFailure(Failure::Invalid, fn () => $this->standard($headers, $body));
    }

    public static function tamperedStandardWebhooks(): iterable
    {
        yield 'body' => [[], '{"test": 1}'];
        yield 'message id' => [['webhook-id' => 'msg_other'], Fixtures::STANDARD_WEBHOOKS_BODY];
        yield 'timestamp' => [['webhook-timestamp' => (string) (Fixtures::STANDARD_WEBHOOKS_TIMESTAMP + 1)], Fixtures::STANDARD_WEBHOOKS_BODY];
    }

    public function testStandardWebhooksRejectsOldMessages(): void
    {
        $this->assertFailure(Failure::TimestampOutOfTolerance, fn () => $this->standard(now: Fixtures::STANDARD_WEBHOOKS_TIMESTAMP + 301));
    }

    #[DataProvider('missingStandardHeaders')]
    public function testStandardWebhooksMissingHeaders(string $header): void
    {
        $this->assertFailure(Failure::Missing, fn () => $this->standard([$header => null]));
    }

    public static function missingStandardHeaders(): iterable
    {
        yield 'id' => ['webhook-id'];
        yield 'timestamp' => ['webhook-timestamp'];
        yield 'signature' => ['webhook-signature'];
    }

    #[DataProvider('malformedStandardHeaders')]
    public function testStandardWebhooksMalformedHeaders(array $headers): void
    {
        $this->assertFailure(Failure::Malformed, fn () => $this->standard($headers));
    }

    public static function malformedStandardHeaders(): iterable
    {
        yield 'only asymmetric signatures' => [['webhook-signature' => 'v1a,c29tZXRoaW5n']];
        yield 'no version' => [['webhook-signature' => 'g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=']];
        yield 'timestamp not numeric' => [['webhook-timestamp' => '2021-02-25T15:02:10Z']];
        yield 'id too long' => [['webhook-id' => str_repeat('x', 257)]];
    }
}
