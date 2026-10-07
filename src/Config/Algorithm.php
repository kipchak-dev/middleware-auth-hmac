<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Config;

/**
 * HMAC digests the kipchak scheme accepts. Set per profile on the server, never chosen by the client,
 * so a client cannot downgrade the algorithm.
 */
enum Algorithm: string
{
    case Sha256 = 'sha256';
    case Sha384 = 'sha384';
    case Sha512 = 'sha512';

    public function hexLength(): int
    {
        return match ($this) {
            self::Sha256 => 64,
            self::Sha384 => 96,
            self::Sha512 => 128,
        };
    }
}
