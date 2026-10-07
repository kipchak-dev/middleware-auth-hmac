<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Exceptions;

/**
 * The replay store could not record or check a signature (connection lost, write refused, ...).
 */
final class ReplayStoreException extends \RuntimeException
{
}
