<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Tests\Unit\Schemes;

use Kipchak\Middleware\Auth\HMAC\Config\Profile;
use Kipchak\Middleware\Auth\HMAC\Exceptions\Failure;
use Kipchak\Middleware\Auth\HMAC\Exceptions\SignatureException;
use Kipchak\Middleware\Auth\HMAC\Schemes\KipchakVerifier;
use Kipchak\Middleware\Auth\HMAC\Tests\Unit\Support\Fixtures;
use Kipchak\Middleware\Auth\HMAC\Tests\Unit\Support\Requests;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

final class KipchakVerifierTest extends TestCase
{
    use Requests;

    private function profile(array $overrides = []): Profile
    {
        return Profile::fromArray('api', $overrides + [
            'keys' => ['client-a' => [Fixtures::KIPCHAK_SECRET, Fixtures::KIPCHAK_ROTATED_SECRET]],
            'signed_headers' => ['content-type'],
        ]);
    }

    private function signedRequest(string $header, array $changes = []): ServerRequestInterface
    {
        return $this->request(
            $changes['method'] ?? 'POST',
            $changes['uri'] ?? Fixtures::KIPCHAK_URI,
            ['Content-Type' => $changes['content-type'] ?? 'application/json', 'Kipchak-Signature' => $header],
            $changes['body'] ?? Fixtures::KIPCHAK_BODY,
        );
    }

    private function verify(ServerRequestInterface $request, ?Profile $profile = null, int $now = Fixtures::NOW): \Kipchak\Middleware\Auth\HMAC\Schemes\VerifiedSignature
    {
        return (new KipchakVerifier())->verify($request, (string) $request->getBody(), $profile ?? $this->profile(), $now);
    }

    private function assertFailure(Failure $expected, callable $callback): void
    {
        try {
            $callback();
            $this->fail("Expected {$expected->value}");
        } catch (SignatureException $exception) {
            $this->assertSame($expected, $exception->failure, $exception->getMessage());
        }
    }

    public function testAcceptsTheIndependentlyComputedVector(): void
    {
        $verified = $this->verify($this->signedRequest(Fixtures::kipchakHeader()));

        $this->assertSame('client-a', $verified->keyId);
        $this->assertSame(Fixtures::NOW, $verified->timestamp);
        $this->assertSame("client-a\n" . Fixtures::KIPCHAK_NONCE, $verified->replayId);
    }

    public function testAcceptsSha512WhenTheProfileUsesIt(): void
    {
        $verified = $this->verify(
            $this->signedRequest(Fixtures::kipchakHeader(Fixtures::KIPCHAK_SHA512_SIGNATURE)),
            $this->profile(['algorithm' => 'sha512'])
        );

        $this->assertSame('client-a', $verified->keyId);
    }

    public function testASha256SignatureIsRejectedByASha512Profile(): void
    {
        $this->assertFailure(Failure::Malformed, fn () => $this->verify(
            $this->signedRequest(Fixtures::kipchakHeader()),
            $this->profile(['algorithm' => 'sha512'])
        ));
    }

    public function testParametersMayComeInAnyOrderWithSpacesAndUpperCaseHex(): void
    {
        $header = ' v1=' . strtoupper(Fixtures::KIPCHAK_SHA256_SIGNATURE) . ', nonce=' . Fixtures::KIPCHAK_NONCE . ' , t=' . Fixtures::NOW . ',keyId=client-a';

        $this->assertSame('client-a', $this->verify($this->signedRequest($header))->keyId);
    }

    public function testAnyOfSeveralV1SignaturesMayMatch(): void
    {
        $header = Fixtures::kipchakHeader(str_repeat('0', 64)) . ',v1=' . Fixtures::KIPCHAK_SHA256_SIGNATURE;

        $this->assertSame('client-a', $this->verify($this->signedRequest($header))->keyId);
    }

    public function testRotatedSecretIsAccepted(): void
    {
        $canonical = \Kipchak\Middleware\Auth\HMAC\Schemes\KipchakCanonicalRequest::build(
            $this->signedRequest(''), Fixtures::KIPCHAK_BODY, ['content-type'], Fixtures::NOW, Fixtures::KIPCHAK_NONCE, 'client-a'
        );
        $signature = hash_hmac('sha256', $canonical, Fixtures::KIPCHAK_ROTATED_SECRET);

        $this->assertSame('client-a', $this->verify($this->signedRequest(Fixtures::kipchakHeader($signature)))->keyId);
    }

    #[DataProvider('tamperedRequests')]
    public function testAnyChangeToASignedPartInvalidatesTheSignature(array $changes): void
    {
        $this->assertFailure(Failure::Invalid, fn () => $this->verify($this->signedRequest(Fixtures::kipchakHeader(), $changes)));
    }

    public static function tamperedRequests(): iterable
    {
        yield 'method' => [['method' => 'PUT']];
        yield 'path' => [['uri' => 'https://api.example.com/v1/refunds?b=2&a=1&a=0&q=hello+world']];
        yield 'query value' => [['uri' => 'https://api.example.com/v1/orders?b=3&a=1&a=0&q=hello+world']];
        yield 'query parameter added' => [['uri' => Fixtures::KIPCHAK_URI . '&admin=1']];
        yield 'signed header' => [['content-type' => 'text/plain']];
        yield 'body' => [['body' => '{"amount":1000}']];
        yield 'body whitespace' => [['body' => '{"amount": 100}']];
    }

    public function testQueryOrderAndHostDoNotMatter(): void
    {
        $verified = $this->verify($this->signedRequest(Fixtures::kipchakHeader(), [
            'uri' => 'http://internal-lb:8080/v1/orders?q=hello%20world&a=0&b=2&a=1',
        ]));

        $this->assertSame('client-a', $verified->keyId);
    }

    #[DataProvider('mutatedHeaders')]
    public function testSignedParametersCannotBeChanged(string $header): void
    {
        $this->assertFailure(Failure::Invalid, fn () => $this->verify($this->signedRequest($header)));
    }

    public static function mutatedHeaders(): iterable
    {
        $signature = Fixtures::KIPCHAK_SHA256_SIGNATURE;

        yield 'timestamp' => ['keyId=client-a,t=1700000001,nonce=' . Fixtures::KIPCHAK_NONCE . ',v1=' . $signature];
        yield 'nonce' => ['keyId=client-a,t=' . Fixtures::NOW . ',nonce=fedcba9876543210,v1=' . $signature];
    }

    public function testUnknownKeyIdIsReportedAsAnInvalidSignature(): void
    {
        $header = 'keyId=client-b,t=' . Fixtures::NOW . ',nonce=' . Fixtures::KIPCHAK_NONCE . ',v1=' . Fixtures::KIPCHAK_SHA256_SIGNATURE;

        try {
            $this->verify($this->signedRequest($header));
            $this->fail('Expected a SignatureException');
        } catch (SignatureException $exception) {
            $this->assertSame(Failure::Invalid, $exception->failure);
            $this->assertStringContainsString('Unknown key ID', $exception->getMessage());
        }
    }

    public function testWrongSecretIsInvalid(): void
    {
        $profile = Profile::fromArray('api', [
            'keys' => ['client-a' => 'a-completely-different-secret'],
            'signed_headers' => ['content-type'],
        ]);

        $this->assertFailure(Failure::Invalid, fn () => $this->verify($this->signedRequest(Fixtures::kipchakHeader()), $profile));
    }

    public function testMissingHeader(): void
    {
        $request = $this->request('POST', Fixtures::KIPCHAK_URI, [], Fixtures::KIPCHAK_BODY);

        $this->assertFailure(Failure::Missing, fn () => $this->verify($request));
    }

    #[DataProvider('malformedHeaders')]
    public function testMalformedHeaders(string $header): void
    {
        $this->assertFailure(Failure::Malformed, fn () => $this->verify($this->signedRequest($header)));
    }

    public static function malformedHeaders(): iterable
    {
        $now = Fixtures::NOW;
        $nonce = Fixtures::KIPCHAK_NONCE;
        $signature = Fixtures::KIPCHAK_SHA256_SIGNATURE;

        yield 'garbage' => ['not a signature'];
        yield 'no key id' => ["t={$now},nonce={$nonce},v1={$signature}"];
        yield 'bad key id' => ["keyId=client a,t={$now},nonce={$nonce},v1={$signature}"];
        yield 'no timestamp' => ["keyId=client-a,nonce={$nonce},v1={$signature}"];
        yield 'timestamp in milliseconds' => ["keyId=client-a,t=1700000000000000,nonce={$nonce},v1={$signature}"];
        yield 'non-numeric timestamp' => ["keyId=client-a,t=yesterday,nonce={$nonce},v1={$signature}"];
        yield 'duplicate timestamp' => ["keyId=client-a,t={$now},t=1,nonce={$nonce},v1={$signature}"];
        yield 'duplicate key id' => ["keyId=client-a,keyId=client-b,t={$now},nonce={$nonce},v1={$signature}"];
        yield 'no nonce' => ["keyId=client-a,t={$now},v1={$signature}"];
        yield 'short nonce' => ["keyId=client-a,t={$now},nonce=abc,v1={$signature}"];
        yield 'no signature' => ["keyId=client-a,t={$now},nonce={$nonce}"];
        yield 'non-hex signature' => ["keyId=client-a,t={$now},nonce={$nonce},v1=" . str_repeat('z', 64)];
        yield 'truncated signature' => ["keyId=client-a,t={$now},nonce={$nonce},v1=" . substr($signature, 0, 63)];
    }

    public function testNonceIsOptionalWhenTheProfileAllowsIt(): void
    {
        $profile = $this->profile(['require_nonce' => false]);
        $canonical = \Kipchak\Middleware\Auth\HMAC\Schemes\KipchakCanonicalRequest::build(
            $this->signedRequest(''), Fixtures::KIPCHAK_BODY, ['content-type'], Fixtures::NOW, null, 'client-a'
        );
        $signature = hash_hmac('sha256', $canonical, Fixtures::KIPCHAK_SECRET);

        $verified = $this->verify($this->signedRequest('keyId=client-a,t=' . Fixtures::NOW . ',v1=' . $signature), $profile);

        // Without a nonce the signature itself identifies the message for replay protection.
        $this->assertSame("client-a\n" . $signature, $verified->replayId);
    }

    #[DataProvider('clockSkews')]
    public function testTimestampTolerance(int $skew, bool $accepted): void
    {
        $verify = fn () => $this->verify($this->signedRequest(Fixtures::kipchakHeader()), null, Fixtures::NOW + $skew);

        if ($accepted) {
            $this->assertSame('client-a', $verify()->keyId);
        } else {
            $this->assertFailure(Failure::TimestampOutOfTolerance, $verify);
        }
    }

    public static function clockSkews(): iterable
    {
        yield 'on time' => [0, true];
        yield 'at the limit (old)' => [300, true];
        yield 'past the limit (old)' => [301, false];
        yield 'at the limit (future)' => [-300, true];
        yield 'past the limit (future)' => [-301, false];
    }

    public function testExpiryIsOnlyReportedForAuthenticSignatures(): void
    {
        $forged = Fixtures::kipchakHeader(str_repeat('a', 64));

        // A forged, expired request reports "invalid", never "expired", so expiry tells an attacker nothing.
        $this->assertFailure(Failure::Invalid, fn () => $this->verify($this->signedRequest($forged), null, Fixtures::NOW + 3600));
    }

    public function testCustomHeaderName(): void
    {
        $request = $this->request('POST', Fixtures::KIPCHAK_URI, [
            'Content-Type' => 'application/json',
            'X-Signature' => Fixtures::kipchakHeader(),
        ], Fixtures::KIPCHAK_BODY);

        $this->assertSame('client-a', $this->verify($request, $this->profile(['header' => 'X-Signature']))->keyId);
    }
}
