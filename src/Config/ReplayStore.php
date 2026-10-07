<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Config;

enum ReplayStore: string
{
    /** kipchak/driver-valkey. Atomic SET NX, shared by every worker and host. Recommended. */
    case Valkey = 'valkey';

    /** kipchak/driver-memcached. Atomic add(), shared by every worker and host. */
    case Memcached = 'memcached';

    /** kipchak/driver-filecache. One host only, and check-then-set (see README). For development. */
    case Filecache = 'filecache';

    /** Any container service that is a NonceStore, a Redis/Valkey or Memcached client, or a PSR-6 pool. */
    case Container = 'container';
}
