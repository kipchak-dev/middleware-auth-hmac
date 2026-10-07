<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Tests\Integration;

use Kipchak\Middleware\Auth\HMAC\Exceptions\ReplayStoreException;
use Kipchak\Middleware\Auth\HMAC\Replay\CacheNonceStore;
use Kipchak\Middleware\Auth\HMAC\Replay\MemcachedNonceStore;
use Kipchak\Middleware\Auth\HMAC\Replay\RedisNonceStore;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\MemcachedAdapter;

final class ReplayStoresTest extends TestCase
{
    use Services;

    private function key(): string
    {
        return 'kipchak.hmac.test.' . bin2hex(random_bytes(8));
    }

    // --- Valkey -----------------------------------------------------------------------------------------------

    public function testValkeyClaimsOnceAndSetsTheTtl(): void
    {
        $valkey = $this->valkey();
        $store = new RedisNonceStore($valkey);
        $key = $this->key();

        $this->assertTrue($store->claim($key, 120));
        $this->assertFalse($store->claim($key, 120));

        $ttl = $valkey->ttl($key);
        $this->assertGreaterThan(115, $ttl);
        $this->assertLessThanOrEqual(120, $ttl);
    }

    public function testValkeyClaimExpires(): void
    {
        $store = new RedisNonceStore($this->valkey());
        $key = $this->key();

        $this->assertTrue($store->claim($key, 1));
        usleep(2_100_000);
        $this->assertTrue($store->claim($key, 1));
    }

    public function testValkeyOutageRaisesAReplayStoreException(): void
    {
        $this->valkey(); // only meaningful alongside the real-service tests
        $disconnected = new \Redis(); // never connected: every command fails

        $this->expectException(ReplayStoreException::class);
        (new RedisNonceStore($disconnected))->claim($this->key(), 60);
    }

    public function testValkeyStoreSwapsInAFreshClientAfterAFailure(): void
    {
        $healthy = $this->valkey();
        $reconnects = 0;
        $store = new RedisNonceStore(new \Redis(), function () use ($healthy, &$reconnects): \Redis {
            $reconnects++;

            return $healthy;
        });
        $key = $this->key();

        $this->assertTrue($store->claim($key, 60), 'The dead client fails, the fresh one records the claim');
        $this->assertFalse($store->claim($key, 60), 'Later claims use the fresh client');
        $this->assertSame(1, $reconnects);
    }

    public function testValkeyStoreFailsClosedWhenReconnectingFails(): void
    {
        $this->valkey(); // only meaningful alongside the real-service tests
        $store = new RedisNonceStore(new \Redis(), static fn (): \Redis => throw new \RedisException('still down'));

        $this->expectException(ReplayStoreException::class);
        $this->expectExceptionMessage('after reconnecting: still down');
        $store->claim($this->key(), 60);
    }

    // --- Memcached --------------------------------------------------------------------------------------------

    public function testMemcachedClaimsOnceAcrossClients(): void
    {
        $store = new MemcachedNonceStore($this->memcached());
        $key = $this->key();

        $this->assertTrue($store->claim($key, 120));
        $this->assertFalse($store->claim($key, 120));
        // A second client (another worker) sees the same claim.
        $this->assertFalse((new MemcachedNonceStore($this->memcached()))->claim($key, 120));
    }

    public function testMemcachedClaimExpires(): void
    {
        $store = new MemcachedNonceStore($this->memcached());
        $key = $this->key();

        $this->assertTrue($store->claim($key, 1));
        usleep(2_100_000);
        $this->assertTrue($store->claim($key, 1));
    }

    public function testMemcachedOutageRaisesAReplayStoreException(): void
    {
        $this->memcached(); // only meaningful alongside the real-service tests

        $this->expectException(ReplayStoreException::class);
        (new MemcachedNonceStore($this->unreachableMemcached()))->claim($this->key(), 60);
    }

    // --- PSR-6 over Memcached ---------------------------------------------------------------------------------

    public function testCacheStoreOverMemcachedClaimsOnceAcrossAdapters(): void
    {
        $store = new CacheNonceStore(new MemcachedAdapter($this->memcached(), 'hmactest'));
        $key = $this->key();

        $this->assertTrue($store->claim($key, 120));
        $this->assertFalse($store->claim($key, 120));
        $this->assertFalse((new CacheNonceStore(new MemcachedAdapter($this->memcached(), 'hmactest')))->claim($key, 120));
    }

    public function testCacheStoreOverMemcachedOutageRaisesAReplayStoreException(): void
    {
        $this->memcached(); // only meaningful alongside the real-service tests

        $this->expectException(ReplayStoreException::class);
        (new CacheNonceStore(new MemcachedAdapter($this->unreachableMemcached(), 'hmactest')))->claim($this->key(), 60);
    }

    // --- Concurrency ------------------------------------------------------------------------------------------

    /**
     * The point of the atomic stores: many workers racing on one signature, exactly one wins.
     * Each worker is a separate PHP process with its own connection, as FrankenPHP workers are.
     */
    #[DataProvider('atomicStores')]
    public function testClaimIsAtomicAcrossProcesses(string $type, string $env, string $default): void
    {
        [$host, $port] = $this->service($env, $default);
        $key = $this->key();
        $start = sprintf('%.6F', microtime(true) + 1.0);
        $workers = 24;

        $processes = [];
        for ($i = 0; $i < $workers; $i++) {
            $command = [PHP_BINARY, __DIR__ . '/claim-worker.php', $type, $host, (string) $port, $key, $start];
            $process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            $this->assertIsResource($process);
            $processes[] = [$process, $pipes];
        }

        $results = [];
        foreach ($processes as [$process, $pipes]) {
            $results[] = trim((string) stream_get_contents($pipes[1])) ?: 'error: ' . stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($process);
        }

        $counts = array_count_values($results);
        ksort($counts);
        $this->assertSame(['lost' => $workers - 1, 'won' => 1], $counts, implode("\n", $results));
    }

    public static function atomicStores(): iterable
    {
        yield 'valkey' => ['valkey', 'HMAC_TEST_VALKEY', '127.0.0.1:56379'];
        yield 'memcached' => ['memcached', 'HMAC_TEST_MEMCACHED', '127.0.0.1:51211'];
    }

    private function unreachableMemcached(): \Memcached
    {
        $client = new \Memcached();
        $client->addServer('127.0.0.1', 1);
        $client->setOption(\Memcached::OPT_CONNECT_TIMEOUT, 100);

        return $client;
    }
}
