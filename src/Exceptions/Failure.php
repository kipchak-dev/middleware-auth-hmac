<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Exceptions;

/**
 * Why a request was rejected. The value is the stable error code returned to clients.
 *
 * Messages are deliberately generic: an unknown key ID and a wrong signature both report
 * "signature_invalid", so the response never helps anyone enumerate keys. The detail goes to the log.
 */
enum Failure: string
{
    case Missing = 'signature_missing';
    case Malformed = 'signature_malformed';
    case Invalid = 'signature_invalid';
    case TimestampOutOfTolerance = 'timestamp_out_of_tolerance';
    case Replayed = 'signature_replayed';
    case BodyTooLarge = 'body_too_large';
    case ReplayStoreUnavailable = 'replay_store_unavailable';

    public function status(): int
    {
        return match ($this) {
            self::BodyTooLarge => 413,
            self::ReplayStoreUnavailable => 503,
            default => 401,
        };
    }

    public function message(): string
    {
        return match ($this) {
            self::Missing => 'The request is not signed.',
            self::Malformed => 'The request signature is malformed.',
            self::Invalid => 'The request signature is invalid.',
            self::TimestampOutOfTolerance => 'The request signature has expired or is not yet valid.',
            self::Replayed => 'The request signature has already been used.',
            self::BodyTooLarge => 'The request body is too large to verify.',
            self::ReplayStoreUnavailable => 'The request could not be verified. Please retry.',
        };
    }
}
