<?php

/*
 * kipchak.auth.hmac.php: request signing and webhook verification.
 * Copy this file into your project's config directory and adjust it.
 */

use function Kipchak\Core\env;

return [
    // true registers verification globally (every request is matched to a profile by path, see below).
    // false lets you attach it per route or group instead:
    //   ->add(new \Kipchak\Middleware\Auth\HMAC\Handlers\VerifySignature($app->getContainer(), 'stripe'))
    'enabled' => true,

    // CORS preflight requests never carry signatures.
    'ignore_options' => true,

    // Exact paths that are never checked.
    'ignore_paths' => [
        '/status',
    ],

    // The profile for requests whose path matches no profile's 'paths'. null leaves those requests
    // unchecked, which suits an API that only needs to verify incoming webhooks.
    'default_profile' => 'api',

    'profiles' => [
        // Signed API calls from your own clients and services (see the README for the signing algorithm,
        // or use \Kipchak\Middleware\Auth\HMAC\Signer::kipchak() from PHP).
        'api' => [
            'scheme' => 'kipchak',
            'header' => 'Kipchak-Signature',
            'algorithm' => 'sha256', // sha256, sha384 or sha512
            'keys' => [
                // key ID => secret (at least 16 bytes; 32+ random bytes recommended). A missing or short secret
                // stops the API at boot rather than accepting requests it cannot verify.
                'billing-service' => env('HMAC_BILLING_SERVICE_SECRET', ''),
                // While rotating, list the new and old secrets; either verifies. Drop the old one once clients have moved.
                // 'mobile-app' => [env('HMAC_MOBILE_APP_SECRET', ''), env('HMAC_MOBILE_APP_PREVIOUS_SECRET', '')],
            ],
            // Headers covered by the signature, in this order. Clients must sign the same list.
            'signed_headers' => ['content-type'],
            'require_nonce' => true,
            'tolerance' => 300, // seconds either side of the server clock
            'max_body_bytes' => 1048576,
        ],

        // Stripe webhooks: https://docs.stripe.com/webhooks#verify-manually
        'stripe' => [
            'scheme' => 'stripe',
            'secrets' => [env('STRIPE_WEBHOOK_SECRET', '')], // "whsec_..."; list two while rolling the secret
            'paths' => ['/webhooks/stripe'],
        ],

        // Any sender that follows the Standard Webhooks spec: https://www.standardwebhooks.com
        // For Svix, add 'header_prefix' => 'svix'.
        'standard' => [
            'scheme' => 'standard-webhooks',
            'secrets' => [env('WEBHOOK_SECRET', '')], // "whsec_" + base64
            'paths' => ['/webhooks/inbound'],
        ],
    ],

    // Replay protection: each signed message is accepted once while its timestamp is within tolerance.
    'replay' => [
        'enabled' => true,
        'store' => 'valkey',     // valkey or memcached (atomic, shared by all workers and hosts),
                                 // filecache (single host, development) or container
        'pool' => 'cache',       // the valkey or memcached pool name from that driver's config
        // 'service' => 'my.store', // for 'container': a NonceStore, Redis/Valkey or Memcached client, or PSR-6 pool
        'prefix' => 'kipchak.hmac',
        'fail_open' => false,    // true accepts requests when the store is down (logged); false answers 503
    ],
];
