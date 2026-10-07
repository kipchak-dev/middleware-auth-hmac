<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Config;

use Kipchak\Middleware\Auth\HMAC\Exceptions\InvalidConfiguration;

final readonly class ReplaySettings
{
    public function __construct(
        public bool $enabled,
        public ReplayStore $store,
        public string $pool,
        public ?string $service,
        public string $prefix,
        public bool $failOpen,
    ) {
    }

    public static function fromArray(array $config): self
    {
        $store = ReplayStore::tryFrom((string) ($config['store'] ?? ReplayStore::Valkey->value))
            ?? throw InvalidConfiguration::at('replay.store', 'must be one of: ' . implode(', ', array_column(ReplayStore::cases(), 'value')));

        $service = $config['service'] ?? null;
        if ($store === ReplayStore::Container && (!is_string($service) || $service === '')) {
            throw InvalidConfiguration::at('replay.service', "must name a container service when replay.store is 'container'");
        }

        // Kept to characters that are legal in PSR-6 keys and Memcached keys alike.
        $prefix = $config['prefix'] ?? 'kipchak.hmac';
        if (!is_string($prefix) || !preg_match('/^[A-Za-z0-9._-]{1,64}$/', $prefix)) {
            throw InvalidConfiguration::at('replay.prefix', 'must be 1-64 characters from A-Z a-z 0-9 . _ -');
        }

        return new self(
            enabled: (bool) ($config['enabled'] ?? true),
            store: $store,
            pool: (string) ($config['pool'] ?? 'cache'),
            service: $service,
            prefix: $prefix,
            failOpen: (bool) ($config['fail_open'] ?? false),
        );
    }
}
