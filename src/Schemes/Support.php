<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Schemes;

use Kipchak\Middleware\Auth\HMAC\Exceptions\Failure;
use Kipchak\Middleware\Auth\HMAC\Exceptions\SignatureException;

/**
 * Parsing and comparison shared by the schemes.
 */
final class Support
{
    /**
     * Parses "a=1,b=2,b=3" into ['a' => ['1'], 'b' => ['2', '3']]. Pieces without "=" are ignored,
     * as Stripe's own libraries do, so unknown future additions to a header do not break verification.
     *
     * @return array<string, list<string>>
     */
    public static function parseParameters(string $header): array
    {
        $parameters = [];
        foreach (explode(',', $header) as $piece) {
            $parts = explode('=', trim($piece), 2);
            if (count($parts) !== 2) {
                continue;
            }
            $parameters[trim($parts[0])][] = trim($parts[1]);
        }

        return $parameters;
    }

    /**
     * @param array<string, list<string>> $parameters
     *
     * @throws SignatureException When the parameter appears more than once.
     */
    public static function single(array $parameters, string $name): ?string
    {
        $values = $parameters[$name] ?? [];
        if (count($values) > 1) {
            throw new SignatureException(Failure::Malformed, "Parameter '{$name}' appears more than once");
        }

        return $values[0] ?? null;
    }

    /**
     * @throws SignatureException
     */
    public static function timestamp(?string $value): int
    {
        if ($value === null || $value === '') {
            throw new SignatureException(Failure::Malformed, 'Timestamp is missing');
        }
        if (!preg_match('/^\d{1,12}$/', $value)) {
            throw new SignatureException(Failure::Malformed, 'Timestamp is not a Unix time in seconds');
        }

        return (int) $value;
    }

    /**
     * @throws SignatureException
     */
    public static function assertWithinTolerance(int $timestamp, int $now, int $tolerance): void
    {
        $age = $now - $timestamp;
        if (abs($age) > $tolerance) {
            throw new SignatureException(
                Failure::TimestampOutOfTolerance,
                $age > 0 ? "Signed {$age}s ago, tolerance is {$tolerance}s" : 'Signed ' . -$age . "s in the future, tolerance is {$tolerance}s"
            );
        }
    }

    /**
     * Constant-time comparison of every provided signature against every expected one.
     * Returns the provided signature that matched, or null.
     *
     * @param list<string> $expected
     * @param list<string> $provided
     */
    public static function firstMatch(array $expected, array $provided): ?string
    {
        foreach ($expected as $candidate) {
            foreach ($provided as $signature) {
                if (hash_equals($candidate, $signature)) {
                    return $signature;
                }
            }
        }

        return null;
    }
}
