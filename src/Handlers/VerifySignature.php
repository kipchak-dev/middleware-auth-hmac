<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Handlers;

use Kipchak\Core\Components\Http;
use Kipchak\Driver\Config\Config;
use Kipchak\Driver\Logger\Logger;
use Kipchak\Middleware\Auth\HMAC\Clock\SystemClock;
use Kipchak\Middleware\Auth\HMAC\Config\Profile;
use Kipchak\Middleware\Auth\HMAC\Config\Settings;
use Kipchak\Middleware\Auth\HMAC\Exceptions\Failure;
use Kipchak\Middleware\Auth\HMAC\Exceptions\ReplayStoreException;
use Kipchak\Middleware\Auth\HMAC\Exceptions\SignatureException;
use Kipchak\Middleware\Auth\HMAC\Replay\NonceStore;
use Kipchak\Middleware\Auth\HMAC\Replay\NonceStoreFactory;
use Kipchak\Middleware\Auth\HMAC\Schemes\VerifiedSignature;
use Psr\Clock\ClockInterface;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Slim\Psr7\Factory\StreamFactory;
use Slim\Psr7\Response;

/**
 * Verifies signed requests and webhooks.
 *
 * Globally (registered by HMAC::initialise), each request is checked against the first profile whose paths
 * cover it, else the default profile; with neither it passes through untouched. On a route or group, pass a
 * profile name to always use that profile:
 *
 *   $app->post('/webhooks/stripe', ...)->add(new VerifySignature($app->getContainer(), 'stripe'));
 *
 * Verified requests carry the request attributes named by the ATTRIBUTE_* constants.
 *
 * Safe in FrankenPHP worker mode: everything held here is built once from config and never changes per request.
 */
final class VerifySignature implements MiddlewareInterface
{
    public const string ATTRIBUTE_PROFILE = 'kipchak.hmac.profile';
    public const string ATTRIBUTE_KEY_ID = 'kipchak.hmac.key_id';
    public const string ATTRIBUTE_TIMESTAMP = 'kipchak.hmac.timestamp';
    public const string ATTRIBUTE_MESSAGE_ID = 'kipchak.hmac.message_id';

    private readonly Settings $settings;
    private readonly ?Profile $forcedProfile;
    private readonly LoggerInterface $logger;
    private readonly ClockInterface $clock;

    /** Resolved on first use, so building the middleware never opens a cache connection. */
    private ?NonceStore $nonceStore;

    /**
     * @param string|null $profile Always verify with this profile, ignoring path matching (for route-level use).
     * @param Settings|null $settings Defaults to the kipchak.auth.hmac config file.
     */
    public function __construct(
        private readonly ContainerInterface $container,
        ?string $profile = null,
        ?Settings $settings = null,
        ?NonceStore $nonceStore = null,
        ?ClockInterface $clock = null,
        ?LoggerInterface $logger = null,
    ) {
        $this->settings = $settings ?? Settings::fromArray(Config::get('kipchak.auth.hmac'));
        $this->forcedProfile = $profile === null ? null : $this->settings->profile($profile);
        $this->nonceStore = $nonceStore;
        $this->clock = $clock ?? new SystemClock();
        $this->logger = $logger ?? Logger::get();

        if ($nonceStore === null && $this->usesReplayProtection()) {
            NonceStoreFactory::assertAvailable($this->settings->replay, $this->container);
        }
    }

    private function usesReplayProtection(): bool
    {
        $profiles = $this->forcedProfile === null ? $this->settings->profiles : [$this->forcedProfile];
        foreach ($profiles as $profile) {
            if ($this->settings->replayEnabledFor($profile)) {
                return true;
            }
        }

        return false;
    }

    public function __invoke(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        return $this->process($request, $handler);
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if ($this->isIgnored($request)) {
            return $handler->handle($request);
        }

        $profile = $this->forcedProfile ?? $this->settings->profileForPath($request->getUri()->getPath());
        if ($profile === null) {
            return $handler->handle($request);
        }

        try {
            [$request, $body] = $this->readBody($request, $profile->maxBodyBytes);
            $verified = $profile->scheme->verifier()->verify($request, $body, $profile, $this->clock->now()->getTimestamp());
            $this->guardAgainstReplay($profile, $verified);
        } catch (SignatureException $exception) {
            $this->logger->warning('HMAC verification failed', [
                'profile' => $profile->name,
                'reason' => $exception->failure->value,
                'detail' => $exception->getMessage(),
                'method' => $request->getMethod(),
                'path' => $request->getUri()->getPath(),
            ]);

            return $this->reject($exception->failure);
        }

        return $handler->handle(
            $request
                ->withAttribute(self::ATTRIBUTE_PROFILE, $profile->name)
                ->withAttribute(self::ATTRIBUTE_KEY_ID, $verified->keyId)
                ->withAttribute(self::ATTRIBUTE_TIMESTAMP, $verified->timestamp)
                ->withAttribute(self::ATTRIBUTE_MESSAGE_ID, $verified->messageId)
        );
    }

    private function isIgnored(ServerRequestInterface $request): bool
    {
        return ($this->settings->ignoreOptions && $request->getMethod() === 'OPTIONS')
            || in_array($request->getUri()->getPath(), $this->settings->ignorePaths, true);
    }

    /**
     * Reads the raw body once and hands downstream a fresh stream holding exactly those bytes, so middleware
     * and controllers after this one still see the full body. Bodies over the profile's limit are refused
     * before being read in full.
     *
     * Downstream never re-reads the original stream. Slim wraps php://input in a caching stream that appends
     * on every read; under FrankenPHP php://input is seekable and is usually read once already by Slim's body
     * parsing middleware, so reading it again and passing it on would leave the route seeing the body twice.
     *
     * @return array{ServerRequestInterface, string}
     *
     * @throws SignatureException
     */
    private function readBody(ServerRequestInterface $request, int $maxBytes): array
    {
        $stream = $request->getBody();

        $size = $stream->getSize();
        if ($size !== null && $size > $maxBytes) {
            throw new SignatureException(Failure::BodyTooLarge, "Body is {$size} bytes, limit is {$maxBytes}");
        }

        if ($stream->isSeekable()) {
            $stream->rewind();
        }

        $body = '';
        while (!$stream->eof()) {
            $chunk = $stream->read(65536);
            if ($chunk === '') {
                break;
            }
            $body .= $chunk;
            if (strlen($body) > $maxBytes) {
                throw new SignatureException(Failure::BodyTooLarge, "Body exceeds the {$maxBytes} byte limit");
            }
        }

        return [$request->withBody((new StreamFactory())->createStream($body)), $body];
    }

    /**
     * @throws SignatureException
     */
    private function guardAgainstReplay(Profile $profile, VerifiedSignature $verified): void
    {
        if (!$this->settings->replayEnabledFor($profile)) {
            return;
        }

        $key = $this->settings->replay->prefix . '.' . hash('sha256', $profile->name . "\n" . $verified->replayId);

        // Remember the signature for exactly as long as it could still pass the timestamp check.
        $ttl = $verified->timestamp + $profile->tolerance - $this->clock->now()->getTimestamp() + 1;

        try {
            $this->nonceStore ??= NonceStoreFactory::create($this->settings->replay, $this->container, $this->logger);
            $firstUse = $this->nonceStore->claim($key, $ttl);
        } catch (ReplayStoreException $exception) {
            if ($this->settings->replay->failOpen) {
                $this->logger->error('HMAC replay store unavailable; accepting the request because replay.fail_open is true', [
                    'profile' => $profile->name,
                    'error' => $exception->getMessage(),
                ]);

                return;
            }

            throw new SignatureException(Failure::ReplayStoreUnavailable, $exception->getMessage(), $exception);
        }

        if (!$firstUse) {
            throw new SignatureException(Failure::Replayed, 'Signature was already used');
        }
    }

    private function reject(Failure $failure): ResponseInterface
    {
        // The status from ErrorStatus, as kipchak/middleware-error writes it: 401 UNAUTHENTICATED, 503 SERVER_ERROR.
        return Http\Response::error(
            new Response(),
            ['error' => $failure->value, 'message' => $failure->message()],
            $failure->status()
        );
    }
}
