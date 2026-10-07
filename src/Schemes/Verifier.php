<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Schemes;

use Kipchak\Middleware\Auth\HMAC\Config\Profile;
use Kipchak\Middleware\Auth\HMAC\Exceptions\SignatureException;
use Psr\Http\Message\ServerRequestInterface;

interface Verifier
{
    /**
     * Checks the signature first and the timestamp second, so "expired" is only ever reported for authentic
     * requests. Replay checking is left to the caller, which only records signatures that verified.
     *
     * @param string $body The raw request body, already read by the caller.
     * @param int $now Unix time.
     *
     * @throws SignatureException
     */
    public function verify(ServerRequestInterface $request, string $body, Profile $profile, int $now): VerifiedSignature;
}
