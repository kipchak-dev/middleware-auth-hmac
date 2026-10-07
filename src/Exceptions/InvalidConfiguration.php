<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Exceptions;

/**
 * Thrown while building the middleware, so a bad kipchak.auth.hmac config fails at boot rather than per request.
 */
final class InvalidConfiguration extends \InvalidArgumentException
{
    public static function at(string $path, string $problem): self
    {
        return new self("kipchak.auth.hmac: {$path} {$problem}");
    }
}
