<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Schemes;

use Psr\Http\Message\RequestInterface;

/**
 * Builds the string a kipchak-scheme signature is computed over. Clients in other languages must build
 * exactly the same string; the README documents it line by line.
 *
 *   KIPCHAK-HMAC-V1
 *   <timestamp>
 *   <nonce, or empty>
 *   <key ID>
 *   <METHOD>
 *   <path>
 *   <canonical query>
 *   <one "name:value" line per signed header, in config order>
 *   <hex SHA-256 of the raw body>
 *
 * Lines are joined with "\n" and there is no trailing newline.
 */
final class KipchakCanonicalRequest
{
    public const string VERSION = 'KIPCHAK-HMAC-V1';

    /**
     * @param list<string> $signedHeaders Lower-case header names.
     */
    public static function build(
        RequestInterface $request,
        string $body,
        array $signedHeaders,
        int $timestamp,
        ?string $nonce,
        string $keyId,
    ): string {
        $lines = [
            self::VERSION,
            (string) $timestamp,
            $nonce ?? '',
            $keyId,
            strtoupper($request->getMethod()),
            self::path($request->getUri()->getPath()),
            self::query($request->getUri()->getQuery()),
        ];

        foreach ($signedHeaders as $name) {
            $lines[] = $name . ':' . self::headerValue($request->getHeader($name));
        }

        $lines[] = hash('sha256', $body);

        return implode("\n", $lines);
    }

    /**
     * The path exactly as sent (still percent-encoded), with a leading slash.
     */
    public static function path(string $path): string
    {
        if ($path === '') {
            return '/';
        }

        return str_starts_with($path, '/') ? $path : '/' . $path;
    }

    /**
     * Query parameters re-encoded with RFC 3986 rules ("+" read as a space) and sorted by name, then value,
     * byte by byte. "a" and "a=" are the same parameter. Empty query → empty line.
     */
    public static function query(string $query): string
    {
        $pairs = [];
        foreach (explode('&', $query) as $part) {
            if ($part === '') {
                continue;
            }
            [$name, $value] = array_pad(explode('=', $part, 2), 2, '');
            $pairs[] = [self::encode($name), self::encode($value)];
        }

        usort($pairs, static fn (array $a, array $b): int => strcmp($a[0], $b[0]) ?: strcmp($a[1], $b[1]));

        return implode('&', array_map(static fn (array $pair): string => $pair[0] . '=' . $pair[1], $pairs));
    }

    /**
     * Each value trimmed with internal whitespace runs collapsed to one space; repeated headers joined with ",".
     * A header the request does not carry signs as an empty value.
     *
     * @param list<string> $values
     */
    public static function headerValue(array $values): string
    {
        return implode(',', array_map(
            static fn (string $value): string => trim((string) preg_replace('/\s+/', ' ', $value)),
            $values
        ));
    }

    private static function encode(string $component): string
    {
        return rawurlencode(rawurldecode(str_replace('+', '%20', $component)));
    }
}
