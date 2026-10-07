<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Tests\Integration;

use PHPUnit\Framework\TestCase;

/**
 * Integration tests need real services. Start them with:
 *
 *   docker run -d --rm --name hmac-valkey -p 56379:6379 valkey/valkey:8-alpine
 *   docker run -d --rm --name hmac-memcached -p 51211:11211 memcached:1.6-alpine
 *
 * Override the addresses with HMAC_TEST_VALKEY and HMAC_TEST_MEMCACHED (host:port). Tests skip when a service
 * is unreachable.
 */
trait Services
{
    /**
     * @return array{string, int}
     */
    protected function service(string $env, string $default): array
    {
        [$host, $port] = explode(':', getenv($env) ?: $default);
        $probe = @fsockopen($host, (int) $port, $errno, $errstr, 0.5);
        if ($probe === false) {
            /** @var TestCase $this */
            $this->markTestSkipped("{$env}: nothing listening on {$host}:{$port}");
        }
        fclose($probe);

        return [$host, (int) $port];
    }

    protected function valkey(): \Redis
    {
        [$host, $port] = $this->service('HMAC_TEST_VALKEY', '127.0.0.1:56379');
        $client = new \Redis();
        $client->connect($host, $port, 1.0);

        return $client;
    }

    protected function memcached(): \Memcached
    {
        [$host, $port] = $this->service('HMAC_TEST_MEMCACHED', '127.0.0.1:51211');
        $client = new \Memcached();
        $client->addServer($host, $port);

        return $client;
    }
}
