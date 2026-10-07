<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Tests\Unit\Replay;

use Kipchak\Middleware\Auth\HMAC\Config\ReplaySettings;
use Kipchak\Middleware\Auth\HMAC\Exceptions\InvalidConfiguration;
use Kipchak\Middleware\Auth\HMAC\Exceptions\ReplayStoreException;
use Kipchak\Middleware\Auth\HMAC\Replay\CacheNonceStore;
use Kipchak\Middleware\Auth\HMAC\Replay\MemcachedNonceStore;
use Kipchak\Middleware\Auth\HMAC\Replay\NonceStoreFactory;
use Kipchak\Middleware\Auth\HMAC\Replay\RedisNonceStore;
use Kipchak\Middleware\Auth\HMAC\Tests\Unit\Support\InMemoryNonceStore;
use DI\Container;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

final class NonceStoresTest extends TestCase
{
    public function testCacheStoreClaimsOnce(): void
    {
        $store = new CacheNonceStore(new ArrayAdapter());

        $this->assertTrue($store->claim('kipchak.hmac.a', 60));
        $this->assertFalse($store->claim('kipchak.hmac.a', 60));
        $this->assertTrue($store->claim('kipchak.hmac.b', 60));
    }

    public function testCacheStoreEntriesExpire(): void
    {
        $pool = new ArrayAdapter();
        $store = new CacheNonceStore($pool);
        $store->claim('kipchak.hmac.a', 1);

        $item = $pool->getItem('kipchak.hmac.a');
        $this->assertTrue($item->isHit());

        sleep(2);
        $this->assertTrue($store->claim('kipchak.hmac.a', 1), 'An expired claim can be made again');
    }

    public function testCacheStoreTreatsARefusedWriteAsAnOutage(): void
    {
        $pool = $this->createStub(CacheItemPoolInterface::class);
        $item = $this->createStub(CacheItemInterface::class);
        $item->method('isHit')->willReturn(false);
        $item->method('set')->willReturnSelf();
        $item->method('expiresAfter')->willReturnSelf();
        $pool->method('getItem')->willReturn($item);
        $pool->method('save')->willReturn(false);

        $this->expectException(ReplayStoreException::class);
        (new CacheNonceStore($pool))->claim('kipchak.hmac.a', 60);
    }

    public function testCacheStoreWrapsPoolExceptions(): void
    {
        $pool = $this->createStub(CacheItemPoolInterface::class);
        $pool->method('getItem')->willThrowException(new \RuntimeException('connection refused'));

        $this->expectException(ReplayStoreException::class);
        $this->expectExceptionMessage('connection refused');
        (new CacheNonceStore($pool))->claim('kipchak.hmac.a', 60);
    }

    public function testFactoryAcceptsContainerServicesOfEachSupportedKind(): void
    {
        $logger = new NullLogger();
        $custom = new InMemoryNonceStore();

        $this->assertSame($custom, NonceStoreFactory::fromService($custom, 'custom', $logger));
        $this->assertInstanceOf(CacheNonceStore::class, NonceStoreFactory::fromService(new ArrayAdapter(), 'pool', $logger));
        $this->assertInstanceOf(RedisNonceStore::class, NonceStoreFactory::fromService(new \Redis(), 'redis', $logger));
        $this->assertInstanceOf(MemcachedNonceStore::class, NonceStoreFactory::fromService(new \Memcached(), 'memcached', $logger));
    }

    public function testFactoryRejectsUnsupportedServices(): void
    {
        $this->expectException(InvalidConfiguration::class);
        $this->expectExceptionMessage('got stdClass');

        NonceStoreFactory::fromService(new \stdClass(), 'thing', new NullLogger());
    }

    public function testFactoryResolvesTheContainerStore(): void
    {
        $container = new Container();
        $container->set('my.nonces', new ArrayAdapter());

        $store = NonceStoreFactory::create(
            ReplaySettings::fromArray(['store' => 'container', 'service' => 'my.nonces']),
            $container,
            new NullLogger()
        );

        $this->assertInstanceOf(CacheNonceStore::class, $store);
    }

    public function testMissingDriverStopsTheMiddlewareBeingBuilt(): void
    {
        $this->expectException(InvalidConfiguration::class);
        $this->expectExceptionMessage('composer require kipchak/driver-valkey');

        new \Kipchak\Middleware\Auth\HMAC\Handlers\VerifySignature(
            new Container(),
            settings: \Kipchak\Middleware\Auth\HMAC\Config\Settings::fromArray(['profiles' => ['api' => ['keys' => ['k' => str_repeat('s', 32)]]]]),
            logger: new NullLogger(),
        );
    }

    public function testMissingDriverDoesNotMatterWhenReplayProtectionIsOff(): void
    {
        $middleware = new \Kipchak\Middleware\Auth\HMAC\Handlers\VerifySignature(
            new Container(),
            settings: \Kipchak\Middleware\Auth\HMAC\Config\Settings::fromArray([
                'profiles' => ['api' => ['keys' => ['k' => str_repeat('s', 32)], 'replay' => false]],
            ]),
            logger: new NullLogger(),
        );

        $this->assertInstanceOf(\Kipchak\Middleware\Auth\HMAC\Handlers\VerifySignature::class, $middleware);
    }

    public function testMissingContainerServiceStopsTheMiddlewareBeingBuilt(): void
    {
        $this->expectException(InvalidConfiguration::class);
        $this->expectExceptionMessage("names 'my.nonces', which is not in the container");

        NonceStoreFactory::assertAvailable(ReplaySettings::fromArray(['store' => 'container', 'service' => 'my.nonces']), new Container());
    }

    public function testFactoryExplainsWhichDriverToInstall(): void
    {
        // None of the cache drivers are installed in this package's own test environment.
        foreach (['valkey' => 'kipchak/driver-valkey', 'memcached' => 'kipchak/driver-memcached', 'filecache' => 'kipchak/driver-filecache'] as $store => $package) {
            try {
                NonceStoreFactory::create(ReplaySettings::fromArray(['store' => $store]), new Container(), new NullLogger());
                $this->fail("Expected {$store} to need {$package}");
            } catch (InvalidConfiguration $exception) {
                $this->assertStringContainsString("composer require {$package}", $exception->getMessage());
            }
        }
    }
}
