<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC;

use Kipchak\Core\Components\App;
use Kipchak\Core\Interfaces;
use Kipchak\Driver\Config\Config;
use Kipchak\Middleware\Auth\HMAC\Handlers\VerifySignature;

final class HMAC implements Interfaces\Middleware
{
    /**
     * Registers signature verification globally when kipchak.auth.hmac has 'enabled' => true.
     * Leave it disabled to attach VerifySignature to individual routes or groups instead.
     */
    public static function initialise(App $app): void
    {
        $config = Config::get('kipchak.auth.hmac');
        if (!empty($config) && ($config['enabled'] ?? false)) {
            $app->add(new VerifySignature($app->getContainer()));
        }
    }
}
