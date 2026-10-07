<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Schemes;

final readonly class VerifiedSignature
{
    /**
     * @param string $replayId Identifies this signed message for replay protection (nonce, message ID or the signature itself).
     * @param int $timestamp The signed Unix timestamp.
     * @param string|null $keyId Kipchak scheme: which client key signed the request.
     * @param string|null $messageId Standard Webhooks scheme: the sender's message ID.
     */
    public function __construct(
        public string $replayId,
        public int $timestamp,
        public ?string $keyId = null,
        public ?string $messageId = null,
    ) {
    }
}
