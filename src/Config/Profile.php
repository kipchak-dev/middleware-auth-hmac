<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Config;

use Kipchak\Middleware\Auth\HMAC\Exceptions\InvalidConfiguration;

/**
 * One named way of verifying requests: which scheme, which secrets, how strict.
 * Built once per worker from config and never mutated, so it is safe to share across requests.
 */
final readonly class Profile
{
    public const string KEY_ID_PATTERN = '/^[A-Za-z0-9._~-]{1,128}$/';
    public const int MINIMUM_SECRET_BYTES = 16;

    /**
     * @param array<string, list<string>> $keys Kipchak scheme: key ID => secrets, newest first. Several secrets allow rotation.
     * @param list<string> $secrets Stripe and Standard Webhooks schemes: accepted secrets (decoded bytes for Standard Webhooks).
     * @param list<string> $signedHeaders Kipchak scheme: lower-case header names covered by the signature.
     * @param list<string> $paths Path prefixes this profile protects when the middleware is global.
     */
    public function __construct(
        public string $name,
        public Scheme $scheme,
        public string $header,
        public Algorithm $algorithm,
        public array $keys,
        public array $secrets,
        public int $tolerance,
        public array $signedHeaders,
        public bool $requireNonce,
        public array $paths,
        public int $maxBodyBytes,
        public bool $replay,
    ) {
    }

    public static function fromArray(string $name, array $config): self
    {
        $at = "profiles.{$name}";

        $scheme = Scheme::tryFrom((string) ($config['scheme'] ?? Scheme::Kipchak->value))
            ?? throw InvalidConfiguration::at("{$at}.scheme", 'must be one of: ' . implode(', ', array_column(Scheme::cases(), 'value')));

        $algorithm = Algorithm::tryFrom((string) ($config['algorithm'] ?? Algorithm::Sha256->value))
            ?? throw InvalidConfiguration::at("{$at}.algorithm", 'must be one of: ' . implode(', ', array_column(Algorithm::cases(), 'value')));

        if ($scheme !== Scheme::Kipchak && $algorithm !== Algorithm::Sha256) {
            throw InvalidConfiguration::at("{$at}.algorithm", "is fixed at sha256 for the {$scheme->value} scheme");
        }

        $header = $config['header'] ?? $config['header_prefix'] ?? $scheme->defaultHeader();
        if (!is_string($header) || !preg_match('/^[A-Za-z0-9-]+$/', $header)) {
            throw InvalidConfiguration::at("{$at}.header", 'must be a valid HTTP header name');
        }

        $keys = [];
        $secrets = [];
        if ($scheme === Scheme::Kipchak) {
            $keys = self::keys($at, $config['keys'] ?? null);
        } else {
            $secrets = self::secrets($at, $scheme, $config['secrets'] ?? null);
        }

        return new self(
            name: $name,
            scheme: $scheme,
            header: $header,
            algorithm: $algorithm,
            keys: $keys,
            secrets: $secrets,
            tolerance: self::positiveInt("{$at}.tolerance", $config['tolerance'] ?? 300),
            signedHeaders: self::signedHeaders($at, $config['signed_headers'] ?? []),
            requireNonce: (bool) ($config['require_nonce'] ?? true),
            paths: self::paths($at, $config['paths'] ?? []),
            maxBodyBytes: self::positiveInt("{$at}.max_body_bytes", $config['max_body_bytes'] ?? 1048576),
            replay: (bool) ($config['replay'] ?? true),
        );
    }

    /**
     * Whether this profile protects the given request path. A prefix matches itself and anything below it
     * on a segment boundary, so "/webhooks" covers "/webhooks/stripe" but not "/webhooksfoo".
     */
    public function matchesPath(string $path): bool
    {
        foreach ($this->paths as $prefix) {
            if ($prefix === '/' || $path === $prefix || str_starts_with($path, rtrim($prefix, '/') . '/')) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<string, list<string>>
     */
    private static function keys(string $at, mixed $keys): array
    {
        if (!is_array($keys) || $keys === []) {
            throw InvalidConfiguration::at("{$at}.keys", 'must map at least one key ID to a secret');
        }

        $normalised = [];
        foreach ($keys as $keyId => $secretOrSecrets) {
            $keyId = (string) $keyId;
            if (!preg_match(self::KEY_ID_PATTERN, $keyId)) {
                throw InvalidConfiguration::at("{$at}.keys", "has an invalid key ID '{$keyId}' (allowed: A-Z a-z 0-9 . _ ~ -, up to 128 characters)");
            }

            $secrets = is_array($secretOrSecrets) ? array_values($secretOrSecrets) : [$secretOrSecrets];
            if ($secrets === []) {
                throw InvalidConfiguration::at("{$at}.keys.{$keyId}", 'must have at least one secret');
            }
            foreach ($secrets as $secret) {
                if (!is_string($secret) || strlen($secret) < self::MINIMUM_SECRET_BYTES) {
                    throw InvalidConfiguration::at("{$at}.keys.{$keyId}", 'secrets must be strings of at least ' . self::MINIMUM_SECRET_BYTES . ' bytes (32 or more recommended)');
                }
            }

            $normalised[$keyId] = $secrets;
        }

        return $normalised;
    }

    /**
     * @return list<string>
     */
    private static function secrets(string $at, Scheme $scheme, mixed $secrets): array
    {
        if (is_string($secrets)) {
            $secrets = [$secrets];
        }
        if (!is_array($secrets) || $secrets === []) {
            throw InvalidConfiguration::at("{$at}.secrets", 'must contain at least one secret');
        }

        $normalised = [];
        foreach (array_values($secrets) as $index => $secret) {
            if (!is_string($secret) || $secret === '') {
                throw InvalidConfiguration::at("{$at}.secrets.{$index}", 'must be a non-empty string');
            }

            if ($scheme === Scheme::StandardWebhooks) {
                // Standard Webhooks secrets are "whsec_" + base64 of the key bytes; the HMAC key is the decoded bytes.
                $decoded = base64_decode(str_starts_with($secret, 'whsec_') ? substr($secret, 6) : $secret, true);
                if ($decoded === false || $decoded === '') {
                    throw InvalidConfiguration::at("{$at}.secrets.{$index}", 'must be base64, optionally prefixed with whsec_');
                }
                $secret = $decoded;
            }

            $normalised[] = $secret;
        }

        return $normalised;
    }

    /**
     * @return list<string>
     */
    private static function signedHeaders(string $at, mixed $headers): array
    {
        if (!is_array($headers)) {
            throw InvalidConfiguration::at("{$at}.signed_headers", 'must be a list of header names');
        }

        $normalised = [];
        foreach ($headers as $header) {
            if (!is_string($header) || !preg_match('/^[A-Za-z0-9-]+$/', $header)) {
                throw InvalidConfiguration::at("{$at}.signed_headers", 'must contain only valid HTTP header names');
            }
            $normalised[] = strtolower($header);
        }

        return array_values(array_unique($normalised));
    }

    /**
     * @return list<string>
     */
    private static function paths(string $at, mixed $paths): array
    {
        if (!is_array($paths)) {
            throw InvalidConfiguration::at("{$at}.paths", 'must be a list of path prefixes');
        }

        foreach ($paths as $path) {
            if (!is_string($path) || !str_starts_with($path, '/')) {
                throw InvalidConfiguration::at("{$at}.paths", "entries must start with '/'");
            }
        }

        return array_values($paths);
    }

    private static function positiveInt(string $at, mixed $value): int
    {
        // Values read through env() arrive as strings.
        if (is_string($value) && ctype_digit($value)) {
            $value = (int) $value;
        }
        if (!is_int($value) || $value < 1) {
            throw InvalidConfiguration::at($at, 'must be a positive integer');
        }

        return $value;
    }
}
