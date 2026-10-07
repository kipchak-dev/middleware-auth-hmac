<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Tests\Unit\Support;

use Psr\Clock\ClockInterface;

final class FrozenClock implements ClockInterface
{
    public function __construct(public int $timestamp)
    {
    }

    public function now(): \DateTimeImmutable
    {
        return new \DateTimeImmutable('@' . $this->timestamp);
    }
}
