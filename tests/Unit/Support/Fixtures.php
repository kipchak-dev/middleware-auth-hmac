<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Tests\Unit\Support;

/**
 * Secrets and vectors shared by the tests. The expected signatures were computed independently with the openssl
 * CLI (see the comments), not with this package, so they pin the wire format rather than echo the code back.
 */
final class Fixtures
{
    public const int NOW = 1700000000;

    public const string KIPCHAK_SECRET = 'kipchak-test-secret-0123456789';
    public const string KIPCHAK_ROTATED_SECRET = 'kipchak-rotated-secret-abcdefghij';
    public const string KIPCHAK_NONCE = '0123456789abcdef';
    public const string KIPCHAK_BODY = '{"amount":100}';
    public const string KIPCHAK_URI = 'https://api.example.com/v1/orders?b=2&a=1&a=0&q=hello+world';

    /*
     * printf 'KIPCHAK-HMAC-V1\n1700000000\n0123456789abcdef\nclient-a\nPOST\n/v1/orders\na=0&a=1&b=2&q=hello%%20world\ncontent-type:application/json\n%s' \
     *   "$(printf '%s' '{"amount":100}' | openssl dgst -sha256 -r | cut -d' ' -f1)" \
     *   | openssl dgst -sha256 -hmac 'kipchak-test-secret-0123456789'
     */
    public const string KIPCHAK_SHA256_SIGNATURE = '9735398f52e93f8a705f0a089ba1f5eac62de957565d7b35d379eb24c5b6466f';
    public const string KIPCHAK_SHA512_SIGNATURE = '8c983b9fdfaf1af903592859fdec4add11c1583dc3ad06c91d3c1a9fdaefaeccce66be0bbf666bc7b29c8865576eff3cec7ebbc7eebda1eba0fc362e7a53f06b';

    public const string STRIPE_SECRET = 'whsec_test_secret_for_kipchak';
    public const string STRIPE_BODY = '{"id":"evt_test","object":"event"}';
    /* printf '1700000000.%s' '{"id":"evt_test","object":"event"}' | openssl dgst -sha256 -hmac 'whsec_test_secret_for_kipchak' */
    public const string STRIPE_SIGNATURE = 'c87c558b1ac5bd70270823ffefc40883b52208a71fd29475b9eb967a84ae60f1';

    /* The worked example published with the Standard Webhooks spec and in Svix's documentation. */
    public const string STANDARD_WEBHOOKS_SECRET = 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw';
    public const string STANDARD_WEBHOOKS_ID = 'msg_p5jXN8AQM9LWM0D4loKWxJek';
    public const int STANDARD_WEBHOOKS_TIMESTAMP = 1614265330;
    public const string STANDARD_WEBHOOKS_BODY = '{"test": 2432232314}';
    public const string STANDARD_WEBHOOKS_SIGNATURE = 'v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=';

    public static function config(array $overrides = []): array
    {
        return array_replace_recursive([
            'enabled' => true,
            'ignore_options' => true,
            'ignore_paths' => ['/status'],
            'default_profile' => 'api',
            'profiles' => [
                'api' => [
                    'scheme' => 'kipchak',
                    'keys' => [
                        'client-a' => [self::KIPCHAK_SECRET, self::KIPCHAK_ROTATED_SECRET],
                    ],
                    'signed_headers' => ['Content-Type'],
                ],
                'stripe' => [
                    'scheme' => 'stripe',
                    'secrets' => [self::STRIPE_SECRET],
                    'paths' => ['/webhooks/stripe'],
                ],
                'standard' => [
                    'scheme' => 'standard-webhooks',
                    'secrets' => [self::STANDARD_WEBHOOKS_SECRET],
                    'paths' => ['/webhooks/standard'],
                ],
            ],
            'replay' => ['enabled' => true, 'store' => 'container', 'service' => 'unused-in-unit-tests'],
        ], $overrides);
    }

    public static function kipchakHeader(string $signature = self::KIPCHAK_SHA256_SIGNATURE): string
    {
        return 'keyId=client-a,t=' . self::NOW . ',nonce=' . self::KIPCHAK_NONCE . ',v1=' . $signature;
    }
}
