<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Tests\Unit\Support;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Response;

/**
 * Stands in for the route: records the request it was given and what body it could read.
 */
final class RecordingHandler implements RequestHandlerInterface
{
    public ?ServerRequestInterface $request = null;
    public ?string $bodySeen = null;

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $this->request = $request;
        $this->bodySeen = $request->getBody()->getContents();

        $response = new Response(200);
        $response->getBody()->write('handled');

        return $response;
    }
}
