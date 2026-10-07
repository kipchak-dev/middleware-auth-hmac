<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Config;

use Kipchak\Middleware\Auth\HMAC\Schemes\KipchakVerifier;
use Kipchak\Middleware\Auth\HMAC\Schemes\StandardWebhooksVerifier;
use Kipchak\Middleware\Auth\HMAC\Schemes\StripeVerifier;
use Kipchak\Middleware\Auth\HMAC\Schemes\Verifier;

/**
 * The signature formats a profile can accept.
 */
enum Scheme: string
{
    /** Signs the whole request (method, path, query, chosen headers, body). For API clients. */
    case Kipchak = 'kipchak';

    /** "Stripe-Signature: t=...,v1=..." over "{t}.{body}". For Stripe and Stripe-style webhook senders. */
    case Stripe = 'stripe';

    /** The Standard Webhooks spec (webhook-id / webhook-timestamp / webhook-signature). https://www.standardwebhooks.com */
    case StandardWebhooks = 'standard-webhooks';

    public function verifier(): Verifier
    {
        return match ($this) {
            self::Kipchak => new KipchakVerifier(),
            self::Stripe => new StripeVerifier(),
            self::StandardWebhooks => new StandardWebhooksVerifier(),
        };
    }

    /**
     * For standard-webhooks this is the header prefix: "webhook" reads webhook-id, webhook-timestamp
     * and webhook-signature ("svix" reads Svix's svix-* headers).
     */
    public function defaultHeader(): string
    {
        return match ($this) {
            self::Kipchak => 'Kipchak-Signature',
            self::Stripe => 'Stripe-Signature',
            self::StandardWebhooks => 'webhook',
        };
    }
}
