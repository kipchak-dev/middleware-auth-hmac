<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC;

use Kipchak\Middleware\Auth\HMAC\Config\Algorithm;
use Kipchak\Middleware\Auth\HMAC\Config\Profile;
use Kipchak\Middleware\Auth\HMAC\Schemes\KipchakVerifier;
use Kipchak\Middleware\Auth\HMAC\Schemes\StandardWebhooksVerifier;
use Kipchak\Middleware\Auth\HMAC\Schemes\StripeVerifier;
use Psr\Http\Message\RequestInterface;

/**
 * The sending side of each scheme: sign outgoing API calls to another Kipchak service, or sign webhooks
 * your API delivers. Uses the same code paths the middleware verifies with.
 */
final class Signer
{
    /**
     * Returns the request with a kipchak-scheme signature header added. Sign last, after every signed header
     * and the body are final.
     *
     * @param list<string> $signedHeaders Must match the server profile's signed_headers, in the same order.
     */
    public static function kipchak(
        RequestInterface $request,
        string $keyId,
        string $secret,
        array $signedHeaders = [],
        Algorithm $algorithm = Algorithm::Sha256,
        string $header = 'Kipchak-Signature',
        ?int $timestamp = null,
        ?string $nonce = null,
    ): RequestInterface {
        if (!preg_match(Profile::KEY_ID_PATTERN, $keyId)) {
            throw new \InvalidArgumentException('Key IDs may only contain A-Z a-z 0-9 . _ ~ - (up to 128 characters)');
        }
        $nonce ??= bin2hex(random_bytes(16));
        if (!preg_match(KipchakVerifier::NONCE_PATTERN, $nonce)) {
            throw new \InvalidArgumentException('Nonces must be 16-128 characters from A-Z a-z 0-9 . _ ~ -');
        }

        $stream = $request->getBody();
        $body = (string) $stream;
        if ($stream->isSeekable()) {
            $stream->rewind();
        }

        $value = KipchakVerifier::header(
            $request,
            $body,
            $keyId,
            $secret,
            array_map('strtolower', $signedHeaders),
            $algorithm,
            $timestamp ?? time(),
            $nonce,
        );

        return $request->withHeader($header, $value);
    }

    /**
     * The Stripe-Signature header value for a webhook body.
     */
    public static function stripe(string $body, string $secret, ?int $timestamp = null): string
    {
        $timestamp ??= time();

        return 't=' . $timestamp . ',v1=' . StripeVerifier::sign(StripeVerifier::payload($timestamp, $body), $secret);
    }

    /**
     * The three Standard Webhooks headers for a webhook body.
     *
     * @param string $secret "whsec_" + base64, as you would share it with the receiver.
     * @return array{'webhook-id': string, 'webhook-timestamp': string, 'webhook-signature': string}
     */
    public static function standardWebhooks(string $messageId, string $body, string $secret, ?int $timestamp = null): array
    {
        $key = base64_decode(str_starts_with($secret, 'whsec_') ? substr($secret, 6) : $secret, true);
        if ($key === false || $key === '') {
            throw new \InvalidArgumentException('Standard Webhooks secrets must be base64, optionally prefixed with whsec_');
        }
        $timestamp ??= time();

        return [
            'webhook-id' => $messageId,
            'webhook-timestamp' => (string) $timestamp,
            'webhook-signature' => 'v1,' . StandardWebhooksVerifier::sign(StandardWebhooksVerifier::content($messageId, $timestamp, $body), $key),
        ];
    }
}
