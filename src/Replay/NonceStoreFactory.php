<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Replay;

use Kipchak\Driver\Filecache\Filecache;
use Kipchak\Driver\Memcached\Memcached;
use Kipchak\Driver\Valkey\Valkey;
use Kipchak\Middleware\Auth\HMAC\Config\ReplaySettings;
use Kipchak\Middleware\Auth\HMAC\Config\ReplayStore;
use Kipchak\Middleware\Auth\HMAC\Exceptions\InvalidConfiguration;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * Builds the configured replay store from whichever cache driver the project has installed.
 * The drivers are optional dependencies, so each is checked for before use.
 */
final class NonceStoreFactory
{
    public static function create(ReplaySettings $settings, ContainerInterface $container, LoggerInterface $logger): NonceStore
    {
        return match ($settings->store) {
            ReplayStore::Valkey => self::valkey($settings->pool, $logger),
            ReplayStore::Memcached => self::memcached($settings->pool, $logger),
            ReplayStore::Filecache => new CacheNonceStore(self::requireDriver(Filecache::class, 'kipchak/driver-filecache')::get()),
            ReplayStore::Container => self::fromService($container->get((string) $settings->service), (string) $settings->service, $logger),
        };
    }

    public static function fromService(mixed $service, string $name, LoggerInterface $logger): NonceStore
    {
        return match (true) {
            $service instanceof NonceStore => $service,
            $service instanceof \RedisArray => self::nonAtomic($service, $name, $logger),
            $service instanceof \Redis,
            $service instanceof \RedisCluster,
            $service instanceof \Relay\Relay,
            $service instanceof \Relay\Cluster,
            $service instanceof \Predis\ClientInterface => new RedisNonceStore($service),
            $service instanceof \Memcached => new MemcachedNonceStore($service),
            $service instanceof CacheItemPoolInterface => new CacheNonceStore($service),
            default => throw InvalidConfiguration::at('replay.service', "'{$name}' must be a NonceStore, a Redis/Valkey or Memcached client, or a PSR-6 pool, got " . get_debug_type($service)),
        };
    }

    /**
     * Checks at boot that the configured store can be built, without connecting to it, so a missing driver
     * stops the API from starting instead of failing the first signed request.
     */
    public static function assertAvailable(ReplaySettings $settings, ContainerInterface $container): void
    {
        match ($settings->store) {
            ReplayStore::Valkey => self::requireDriver(Valkey::class, 'kipchak/driver-valkey'),
            ReplayStore::Memcached => self::requireDriver(Memcached::class, 'kipchak/driver-memcached'),
            ReplayStore::Filecache => self::requireDriver(Filecache::class, 'kipchak/driver-filecache'),
            ReplayStore::Container => $container->has((string) $settings->service)
                ?: throw InvalidConfiguration::at('replay.service', "names '{$settings->service}', which is not in the container"),
        };
    }

    private static function valkey(string $pool, LoggerInterface $logger): NonceStore
    {
        $valkey = self::requireDriver(Valkey::class, 'kipchak/driver-valkey');

        // Valkey::connection() arrived in a later driver release; older ones only expose the PSR-6 adapter.
        if (!method_exists($valkey, 'connection')) {
            $logger->warning('kipchak.auth.hmac: this kipchak/driver-valkey has no connection() method, so replay checks are check-then-set rather than atomic. Upgrade the driver.');

            return new CacheNonceStore($valkey::get($pool));
        }

        $connection = $valkey::connection($pool);
        if ($connection instanceof \RedisArray) {
            return self::nonAtomic($connection, "valkey pool '{$pool}'", $logger);
        }

        // Valkey::reconnect() arrived alongside connection(); guard anyway so a partial upgrade still works.
        $reconnect = method_exists($valkey, 'reconnect')
            ? static fn () => $valkey::reconnect($pool)
            : null;

        return new RedisNonceStore($connection, $reconnect);
    }

    private static function memcached(string $pool, LoggerInterface $logger): NonceStore
    {
        $memcached = self::requireDriver(Memcached::class, 'kipchak/driver-memcached');

        // Memcached::connection() arrived in a later driver release; older ones only expose the PSR-6 adapter.
        if (!method_exists($memcached, 'connection')) {
            $logger->warning('kipchak.auth.hmac: this kipchak/driver-memcached has no connection() method, so replay checks are check-then-set rather than atomic. Upgrade the driver.');

            return new CacheNonceStore($memcached::get($pool));
        }

        return new MemcachedNonceStore($memcached::connection($pool));
    }

    /**
     * RedisArray shards keys client-side and has no SET NX with options, so it goes through a PSR-6 adapter.
     */
    private static function nonAtomic(\RedisArray $client, string $name, LoggerInterface $logger): NonceStore
    {
        if (!class_exists(\Symfony\Component\Cache\Adapter\RedisAdapter::class)) {
            throw InvalidConfiguration::at('replay.service', "'{$name}' is a RedisArray, which needs symfony/cache. Use cluster mode or a PSR-6 pool instead.");
        }

        $logger->warning("kipchak.auth.hmac: {$name} is a RedisArray, so replay checks are check-then-set rather than atomic. Use cluster mode for atomic checks.");

        return new CacheNonceStore(new \Symfony\Component\Cache\Adapter\RedisAdapter($client));
    }

    /**
     * @template T of object
     * @param class-string<T> $class
     * @return class-string<T>
     */
    private static function requireDriver(string $class, string $package): string
    {
        if (!class_exists($class)) {
            throw InvalidConfiguration::at('replay.store', "needs {$package}. Install it with: composer require {$package}");
        }

        return $class;
    }
}
