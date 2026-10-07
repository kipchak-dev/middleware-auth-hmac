<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Schemes;

use Kipchak\Middleware\Auth\HMAC\Config\Profile;
use Kipchak\Middleware\Auth\HMAC\Exceptions\Failure;
use Kipchak\Middleware\Auth\HMAC\Exceptions\SignatureException;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The Standard Webhooks spec (https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md):
 *
 *   webhook-id: msg_...
 *   webhook-timestamp: <unix>
 *   webhook-signature: v1,<base64 hmac-sha256 of "{id}.{timestamp}.{body}"> [v1,<...>]
 *
 * The profile's header setting is the prefix ("webhook" by default, "svix" for Svix). Only symmetric "v1"
 * signatures are supported; asymmetric "v1a" entries are ignored.
 */
final class StandardWebhooksVerifier implements Verifier
{
    public function verify(ServerRequestInterface $request, string $body, Profile $profile, int $now): VerifiedSignature
    {
        $prefix = $profile->header;
        $messageId = $request->getHeaderLine("{$prefix}-id");
        $timestampHeader = $request->getHeaderLine("{$prefix}-timestamp");
        $signatureHeader = $request->getHeaderLine("{$prefix}-signature");

        if ($messageId === '' || $timestampHeader === '' || $signatureHeader === '') {
            throw new SignatureException(Failure::Missing, "Expected {$prefix}-id, {$prefix}-timestamp and {$prefix}-signature headers");
        }
        if (strlen($messageId) > 256) {
            throw new SignatureException(Failure::Malformed, "{$prefix}-id is longer than 256 characters");
        }

        $timestamp = Support::timestamp($timestampHeader);

        $signatures = [];
        foreach (preg_split('/\s+/', trim($signatureHeader)) ?: [] as $entry) {
            $parts = explode(',', $entry, 2);
            if (count($parts) === 2 && $parts[0] === 'v1' && $parts[1] !== '') {
                $signatures[] = $parts[1];
            }
        }
        if ($signatures === []) {
            throw new SignatureException(Failure::Malformed, 'No v1 signature');
        }

        $content = self::content($messageId, $timestamp, $body);
        $expected = array_map(static fn (string $key): string => self::sign($content, $key), $profile->secrets);

        Support::firstMatch($expected, $signatures)
            ?? throw new SignatureException(Failure::Invalid, 'Signature does not match any configured secret');

        Support::assertWithinTolerance($timestamp, $now, $profile->tolerance);

        // A sender's retry keeps the message ID but is signed with a new timestamp, so ID + timestamp blocks exact
        // replays without rejecting legitimate retries. Deduplicating retries by message ID is the application's job.
        return new VerifiedSignature(replayId: $messageId . "\n" . $timestamp, timestamp: $timestamp, messageId: $messageId);
    }

    public static function content(string $messageId, int $timestamp, string $body): string
    {
        return $messageId . '.' . $timestamp . '.' . $body;
    }

    /**
     * @param string $key The decoded secret bytes (not the "whsec_" string).
     */
    public static function sign(string $content, string $key): string
    {
        return base64_encode(hash_hmac('sha256', $content, $key, true));
    }
}
