<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Exceptions;

/**
 * A request failed verification. The message is for logs only and must never contain secrets or signatures.
 */
final class SignatureException extends \RuntimeException
{
    public function __construct(public readonly Failure $failure, string $detail, ?\Throwable $previous = null)
    {
        parent::__construct($detail, 0, $previous);
    }
}
