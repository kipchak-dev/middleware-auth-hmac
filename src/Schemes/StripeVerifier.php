<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Schemes;

use Kipchak\Middleware\Auth\HMAC\Config\Profile;
use Kipchak\Middleware\Auth\HMAC\Exceptions\Failure;
use Kipchak\Middleware\Auth\HMAC\Exceptions\SignatureException;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Stripe-Signature: t=<unix>,v1=<hex hmac-sha256 of "{t}.{body}">[,v1=...][,v0=...]
 *
 * Matches https://docs.stripe.com/webhooks#verify-manually. The endpoint secret ("whsec_...") is used as the key
 * exactly as given. v0 and any other schemes are ignored.
 */
final class StripeVerifier implements Verifier
{
    public function verify(ServerRequestInterface $request, string $body, Profile $profile, int $now): VerifiedSignature
    {
        $header = $request->getHeaderLine($profile->header);
        if ($header === '') {
            throw new SignatureException(Failure::Missing, "No {$profile->header} header");
        }

        $parameters = Support::parseParameters($header);
        $timestamp = Support::timestamp(Support::single($parameters, 't'));
        $signatures = array_map('strtolower', $parameters['v1'] ?? []);
        if ($signatures === []) {
            throw new SignatureException(Failure::Malformed, 'No v1 signature');
        }

        $payload = self::payload($timestamp, $body);
        $expected = array_map(static fn (string $secret): string => self::sign($payload, $secret), $profile->secrets);

        $matched = Support::firstMatch($expected, $signatures)
            ?? throw new SignatureException(Failure::Invalid, 'Signature does not match any configured secret');

        Support::assertWithinTolerance($timestamp, $now, $profile->tolerance);

        // Stripe signs every delivery attempt afresh, so a retried event carries a new signature and is not a replay.
        return new VerifiedSignature(replayId: $matched, timestamp: $timestamp);
    }

    public static function payload(int $timestamp, string $body): string
    {
        return $timestamp . '.' . $body;
    }

    public static function sign(string $payload, string $secret): string
    {
        return hash_hmac('sha256', $payload, $secret);
    }
}
