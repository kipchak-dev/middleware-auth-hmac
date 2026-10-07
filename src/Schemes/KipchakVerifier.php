<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Schemes;

use Kipchak\Middleware\Auth\HMAC\Config\Algorithm;
use Kipchak\Middleware\Auth\HMAC\Config\Profile;
use Kipchak\Middleware\Auth\HMAC\Exceptions\Failure;
use Kipchak\Middleware\Auth\HMAC\Exceptions\SignatureException;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Kipchak-Signature: keyId=<id>,t=<unix>,nonce=<random>,v1=<hex hmac>
 *
 * Several v1 values may be sent while a client rotates secrets.
 */
final class KipchakVerifier implements Verifier
{
    public const string NONCE_PATTERN = '/^[A-Za-z0-9._~-]{16,128}$/';

    public function verify(ServerRequestInterface $request, string $body, Profile $profile, int $now): VerifiedSignature
    {
        $header = $request->getHeaderLine($profile->header);
        if ($header === '') {
            throw new SignatureException(Failure::Missing, "No {$profile->header} header");
        }

        $parameters = Support::parseParameters($header);
        $keyId = Support::single($parameters, 'keyId');
        $timestamp = Support::timestamp(Support::single($parameters, 't'));
        $nonce = Support::single($parameters, 'nonce');
        $signatures = array_map('strtolower', $parameters['v1'] ?? []);

        if ($keyId === null || !preg_match(Profile::KEY_ID_PATTERN, $keyId)) {
            throw new SignatureException(Failure::Malformed, 'keyId is missing or invalid');
        }
        if ($nonce === null && $profile->requireNonce) {
            throw new SignatureException(Failure::Malformed, 'nonce is required by this profile');
        }
        if ($nonce !== null && !preg_match(self::NONCE_PATTERN, $nonce)) {
            throw new SignatureException(Failure::Malformed, 'nonce must be 16-128 characters from A-Z a-z 0-9 . _ ~ -');
        }
        if ($signatures === []) {
            throw new SignatureException(Failure::Malformed, 'No v1 signature');
        }
        foreach ($signatures as $signature) {
            if (strlen($signature) !== $profile->algorithm->hexLength() || !ctype_xdigit($signature)) {
                throw new SignatureException(Failure::Malformed, "v1 must be a hex {$profile->algorithm->value} HMAC");
            }
        }

        $secrets = $profile->keys[$keyId]
            ?? throw new SignatureException(Failure::Invalid, "Unknown key ID '{$keyId}'");

        $canonical = KipchakCanonicalRequest::build($request, $body, $profile->signedHeaders, $timestamp, $nonce, $keyId);
        $expected = array_map(static fn (string $secret): string => self::sign($profile->algorithm, $canonical, $secret), $secrets);

        $matched = Support::firstMatch($expected, $signatures)
            ?? throw new SignatureException(Failure::Invalid, "Signature does not match for key ID '{$keyId}'");

        Support::assertWithinTolerance($timestamp, $now, $profile->tolerance);

        // With a nonce, two identical requests in the same second stay distinct. Without one, the signature itself is the identity.
        return new VerifiedSignature(
            replayId: $keyId . "\n" . ($nonce ?? $matched),
            timestamp: $timestamp,
            keyId: $keyId,
        );
    }

    public static function sign(Algorithm $algorithm, string $canonicalRequest, string $secret): string
    {
        return hash_hmac($algorithm->value, $canonicalRequest, $secret);
    }

    /**
     * The header value for a request. Used by the Signer; kept here so signing and verifying share one definition.
     *
     * @param list<string> $signedHeaders
     */
    public static function header(
        RequestInterface $request,
        string $body,
        string $keyId,
        string $secret,
        array $signedHeaders,
        Algorithm $algorithm,
        int $timestamp,
        ?string $nonce,
    ): string {
        $canonical = KipchakCanonicalRequest::build($request, $body, $signedHeaders, $timestamp, $nonce, $keyId);

        $parameters = ['keyId=' . $keyId, 't=' . $timestamp];
        if ($nonce !== null) {
            $parameters[] = 'nonce=' . $nonce;
        }
        $parameters[] = 'v1=' . self::sign($algorithm, $canonical, $secret);

        return implode(',', $parameters);
    }
}
