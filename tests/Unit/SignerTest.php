<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Tests\Unit;

use Kipchak\Middleware\Auth\HMAC\Config\Algorithm;
use Kipchak\Middleware\Auth\HMAC\Config\Profile;
use Kipchak\Middleware\Auth\HMAC\Schemes\KipchakVerifier;
use Kipchak\Middleware\Auth\HMAC\Schemes\StandardWebhooksVerifier;
use Kipchak\Middleware\Auth\HMAC\Schemes\StripeVerifier;
use Kipchak\Middleware\Auth\HMAC\Signer;
use Kipchak\Middleware\Auth\HMAC\Tests\Unit\Support\Fixtures;
use Kipchak\Middleware\Auth\HMAC\Tests\Unit\Support\Requests;
use PHPUnit\Framework\TestCase;

final class SignerTest extends TestCase
{
    use Requests;

    public function testKipchakSignerReproducesTheReferenceVector(): void
    {
        $request = $this->request('POST', Fixtures::KIPCHAK_URI, ['Content-Type' => 'application/json'], Fixtures::KIPCHAK_BODY);

        $signed = Signer::kipchak($request, 'client-a', Fixtures::KIPCHAK_SECRET, ['Content-Type'], timestamp: Fixtures::NOW, nonce: Fixtures::KIPCHAK_NONCE);

        $this->assertSame(Fixtures::kipchakHeader(), $signed->getHeaderLine('Kipchak-Signature'));
    }

    public function testKipchakSignerLeavesTheBodyReadable(): void
    {
        $request = $this->request('POST', Fixtures::KIPCHAK_URI, [], Fixtures::KIPCHAK_BODY);

        $signed = Signer::kipchak($request, 'client-a', Fixtures::KIPCHAK_SECRET);

        $this->assertSame(Fixtures::KIPCHAK_BODY, $signed->getBody()->getContents());
    }

    public function testKipchakSignerGeneratesFreshNoncesAndTheCurrentTime(): void
    {
        $request = $this->request('GET', 'https://api.example.com/v1/orders');
        $first = Signer::kipchak($request, 'client-a', Fixtures::KIPCHAK_SECRET)->getHeaderLine('Kipchak-Signature');
        $second = Signer::kipchak($request, 'client-a', Fixtures::KIPCHAK_SECRET)->getHeaderLine('Kipchak-Signature');

        $this->assertNotSame($first, $second);
        $this->assertMatchesRegularExpression('/^keyId=client-a,t=\d+,nonce=[0-9a-f]{32},v1=[0-9a-f]{64}$/', $first);
        preg_match('/t=(\d+)/', $first, $matches);
        $this->assertEqualsWithDelta(time(), (int) $matches[1], 5);
    }

    public function testKipchakSignerRoundTripsWithEveryAlgorithmAndACustomHeader(): void
    {
        foreach (Algorithm::cases() as $algorithm) {
            $profile = Profile::fromArray('api', [
                'keys' => ['client-a' => Fixtures::KIPCHAK_SECRET],
                'algorithm' => $algorithm->value,
                'header' => 'X-Signature',
                'signed_headers' => ['x-tenant', 'content-type'],
            ]);
            $request = $this->request('DELETE', 'https://api.example.com/v1/orders/9?force=true', ['X-Tenant' => 'acme', 'Content-Type' => 'text/plain'], 'bye');

            $signed = Signer::kipchak($request, 'client-a', Fixtures::KIPCHAK_SECRET, ['X-Tenant', 'Content-Type'], $algorithm, 'X-Signature', Fixtures::NOW);

            $verified = (new KipchakVerifier())->verify($signed, 'bye', $profile, Fixtures::NOW);
            $this->assertSame('client-a', $verified->keyId, $algorithm->value);
        }
    }

    public function testKipchakSignerRejectsBadKeyIdsAndNonces(): void
    {
        $request = $this->request('GET');

        try {
            Signer::kipchak($request, 'bad key', Fixtures::KIPCHAK_SECRET);
            $this->fail('Expected an exception for the key ID');
        } catch (\InvalidArgumentException) {
        }

        $this->expectException(\InvalidArgumentException::class);
        Signer::kipchak($request, 'client-a', Fixtures::KIPCHAK_SECRET, nonce: 'short');
    }

    public function testStripeSignerReproducesTheReferenceVectorAndRoundTrips(): void
    {
        $header = Signer::stripe(Fixtures::STRIPE_BODY, Fixtures::STRIPE_SECRET, Fixtures::NOW);
        $this->assertSame('t=' . Fixtures::NOW . ',v1=' . Fixtures::STRIPE_SIGNATURE, $header);

        $request = $this->request('POST', 'https://api.example.com/webhooks/stripe', ['Stripe-Signature' => $header], Fixtures::STRIPE_BODY);
        $profile = Profile::fromArray('stripe', ['scheme' => 'stripe', 'secrets' => [Fixtures::STRIPE_SECRET]]);

        $this->assertSame(Fixtures::NOW, (new StripeVerifier())->verify($request, Fixtures::STRIPE_BODY, $profile, Fixtures::NOW)->timestamp);
    }

    public function testStandardWebhooksSignerReproducesTheSpecVectorAndRoundTrips(): void
    {
        $headers = Signer::standardWebhooks(
            Fixtures::STANDARD_WEBHOOKS_ID,
            Fixtures::STANDARD_WEBHOOKS_BODY,
            Fixtures::STANDARD_WEBHOOKS_SECRET,
            Fixtures::STANDARD_WEBHOOKS_TIMESTAMP
        );
        $this->assertSame(Fixtures::STANDARD_WEBHOOKS_SIGNATURE, $headers['webhook-signature']);

        $request = $this->request('POST', 'https://api.example.com/webhooks/standard', $headers, Fixtures::STANDARD_WEBHOOKS_BODY);
        $profile = Profile::fromArray('standard', ['scheme' => 'standard-webhooks', 'secrets' => [Fixtures::STANDARD_WEBHOOKS_SECRET]]);

        $verified = (new StandardWebhooksVerifier())->verify($request, Fixtures::STANDARD_WEBHOOKS_BODY, $profile, Fixtures::STANDARD_WEBHOOKS_TIMESTAMP);
        $this->assertSame(Fixtures::STANDARD_WEBHOOKS_ID, $verified->messageId);
    }

    public function testStandardWebhooksSignerRejectsANonBase64Secret(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        Signer::standardWebhooks('msg_1', '{}', 'whsec_***');
    }
}
