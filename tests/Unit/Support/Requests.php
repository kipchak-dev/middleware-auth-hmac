<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Tests\Unit\Support;

use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Factory\StreamFactory;

trait Requests
{
    /**
     * @param array<string, string|list<string>> $headers
     */
    protected function request(
        string $method = 'POST',
        string $uri = 'https://api.example.com/v1/orders',
        array $headers = [],
        string $body = '',
    ): ServerRequestInterface {
        $request = (new ServerRequestFactory())->createServerRequest($method, $uri);
        foreach ($headers as $name => $value) {
            $request = $request->withHeader($name, $value);
        }

        return $request->withBody((new StreamFactory())->createStream($body));
    }
}
