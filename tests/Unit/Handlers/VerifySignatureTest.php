<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Tests\Unit\Handlers;

use DI\Container;
use Kipchak\Middleware\Auth\HMAC\Config\Settings;
use Kipchak\Middleware\Auth\HMAC\Handlers\VerifySignature;
use Kipchak\Middleware\Auth\HMAC\Signer;
use Kipchak\Middleware\Auth\HMAC\Tests\Unit\Support\Fixtures;
use Kipchak\Middleware\Auth\HMAC\Tests\Unit\Support\FrozenClock;
use Kipchak\Middleware\Auth\HMAC\Tests\Unit\Support\InMemoryNonceStore;
use Kipchak\Middleware\Auth\HMAC\Tests\Unit\Support\RecordingHandler;
use Kipchak\Middleware\Auth\HMAC\Tests\Unit\Support\Requests;
use Monolog\Handler\TestHandler;
use Monolog\Logger;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;

final class VerifySignatureTest extends TestCase
{
    use Requests;

    private InMemoryNonceStore $store;
    private FrozenClock $clock;
    private TestHandler $log;
    private RecordingHandler $handler;

    protected function setUp(): void
    {
        $this->store = new InMemoryNonceStore();
        $this->clock = new FrozenClock(Fixtures::NOW);
        $this->log = new TestHandler();
        $this->handler = new RecordingHandler();
    }

    private function middleware(array $config = [], ?string $profile = null): VerifySignature
    {
        return new VerifySignature(
            new Container(),
            profile: $profile,
            settings: Settings::fromArray(Fixtures::config($config)),
            nonceStore: $this->store,
            clock: $this->clock,
            logger: new Logger('test', [$this->log]),
        );
    }

    private function signedApiRequest(): ServerRequestInterface
    {
        return $this->request('POST', Fixtures::KIPCHAK_URI, [
            'Content-Type' => 'application/json',
            'Kipchak-Signature' => Fixtures::kipchakHeader(),
        ], Fixtures::KIPCHAK_BODY);
    }

    private function assertRejected(ResponseInterface $response, int $status, string $error): void
    {
        $this->assertSame($status, $response->getStatusCode());
        $this->assertSame('application/json', $response->getHeaderLine('Content-Type'));
        $this->assertNull($this->handler->request, 'The route must not run');

        $payload = json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);
        $this->assertSame($status, $payload['code']);
        $this->assertSame($error, $payload['data']['error']);
        $this->assertIsString($payload['data']['message']);
    }

    public function testValidRequestReachesTheRouteWithAttributesAndAReadableBody(): void
    {
        $response = $this->middleware()->process($this->signedApiRequest(), $this->handler);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame(Fixtures::KIPCHAK_BODY, $this->handler->bodySeen);
        $this->assertSame('api', $this->handler->request->getAttribute(VerifySignature::ATTRIBUTE_PROFILE));
        $this->assertSame('client-a', $this->handler->request->getAttribute(VerifySignature::ATTRIBUTE_KEY_ID));
        $this->assertSame(Fixtures::NOW, $this->handler->request->getAttribute(VerifySignature::ATTRIBUTE_TIMESTAMP));
        $this->assertNull($this->handler->request->getAttribute(VerifySignature::ATTRIBUTE_MESSAGE_ID));
    }

    public function testInvokableLikeTheOtherKipchakMiddlewares(): void
    {
        $response = ($this->middleware())($this->signedApiRequest(), $this->handler);

        $this->assertSame(200, $response->getStatusCode());
    }

    public function testBodyIsReadFromTheStartEvenIfSomethingAlreadyReadIt(): void
    {
        $request = $this->signedApiRequest();
        $request->getBody()->getContents(); // leaves the pointer at the end

        $this->assertSame(200, $this->middleware()->process($request, $this->handler)->getStatusCode());
        $this->assertSame(Fixtures::KIPCHAK_BODY, $this->handler->bodySeen);
    }

    /**
     * Slim builds the request body from php://input with a php://temp cache, and every read() appends to that
     * cache. Under FrankenPHP php://input reports itself seekable, and Slim's body parsing middleware (added
     * after Api::boot, so it runs first) has already read it once. Reading it a second time used to leave the
     * route seeing the body twice.
     */
    public function testSlimCachedInputStreamAlreadyReadUpstreamIsNotDuplicated(): void
    {
        $input = fopen('php://temp', 'w+');
        fwrite($input, Fixtures::KIPCHAK_BODY);
        rewind($input);
        $body = new \Slim\Psr7\Stream($input, new \Slim\Psr7\Stream(fopen('php://temp', 'w+')));
        $this->assertSame(Fixtures::KIPCHAK_BODY, (string) $body, 'Upstream body parsing reads it first');

        $request = $this->signedApiRequest()->withBody($body);

        $this->assertSame(200, $this->middleware()->process($request, $this->handler)->getStatusCode());
        $this->assertSame(Fixtures::KIPCHAK_BODY, (string) $this->handler->request->getBody());
    }

    public function testNonSeekableBodyIsReplacedSoTheRouteCanStillReadIt(): void
    {
        $request = $this->signedApiRequest();
        $request = $request->withBody(new OneShotStream(Fixtures::KIPCHAK_BODY));

        $this->assertSame(200, $this->middleware()->process($request, $this->handler)->getStatusCode());
        $this->assertSame(Fixtures::KIPCHAK_BODY, $this->handler->bodySeen);
    }

    public function testInvalidSignatureIsRejectedAndLoggedWithoutSecrets(): void
    {
        $request = $this->signedApiRequest()->withHeader('Kipchak-Signature', Fixtures::kipchakHeader(str_repeat('a', 64)));

        $this->assertRejected($this->middleware()->process($request, $this->handler), 401, 'signature_invalid');

        $records = $this->log->getRecords();
        $this->assertCount(1, $records);
        $this->assertSame('HMAC verification failed', $records[0]->message);
        $this->assertSame('signature_invalid', $records[0]->context['reason']);
        $this->assertSame('api', $records[0]->context['profile']);
        $logged = json_encode($records[0]->toArray());
        $this->assertStringNotContainsString(Fixtures::KIPCHAK_SECRET, $logged);
        $this->assertStringNotContainsString(str_repeat('a', 64), $logged);
    }

    public function testUnsignedRequestIsRejected(): void
    {
        $request = $this->request('POST', Fixtures::KIPCHAK_URI, [], Fixtures::KIPCHAK_BODY);

        $this->assertRejected($this->middleware()->process($request, $this->handler), 401, 'signature_missing');
    }

    public function testExpiredRequestIsRejected(): void
    {
        $this->clock->timestamp = Fixtures::NOW + 301;

        $this->assertRejected($this->middleware()->process($this->signedApiRequest(), $this->handler), 401, 'timestamp_out_of_tolerance');
    }

    public function testReplayIsRejected(): void
    {
        $middleware = $this->middleware();

        $this->assertSame(200, $middleware->process($this->signedApiRequest(), $this->handler)->getStatusCode());

        $this->handler = new RecordingHandler();
        $this->assertRejected($middleware->process($this->signedApiRequest(), $this->handler), 401, 'signature_replayed');
    }

    public function testReplayKeyIsPrefixedHashedAndKeptOnlyWhileTheSignatureCouldVerify(): void
    {
        $this->clock->timestamp = Fixtures::NOW + 100;

        $this->middleware()->process($this->signedApiRequest(), $this->handler);

        $this->assertCount(1, $this->store->claims);
        $key = array_key_first($this->store->claims);
        $this->assertSame('kipchak.hmac.' . hash('sha256', "api\nclient-a\n" . Fixtures::KIPCHAK_NONCE), $key);
        // Signed at NOW, valid until NOW + 300, checked at NOW + 100: 200 seconds left, plus one.
        $this->assertSame(201, $this->store->claims[$key]);
    }

    public function testFailedVerificationsDoNotBurnNonces(): void
    {
        $forged = $this->signedApiRequest()->withHeader('Kipchak-Signature', Fixtures::kipchakHeader(str_repeat('a', 64)));
        $this->middleware()->process($forged, $this->handler);

        $this->assertSame([], $this->store->claims);
    }

    public function testReplayStoreOutageFailsClosedByDefault(): void
    {
        $this->store->broken = true;

        $this->assertRejected($this->middleware()->process($this->signedApiRequest(), $this->handler), 503, 'replay_store_unavailable');
    }

    public function testReplayStoreOutageCanFailOpen(): void
    {
        $this->store->broken = true;

        $response = $this->middleware(['replay' => ['fail_open' => true]])->process($this->signedApiRequest(), $this->handler);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertTrue($this->log->hasErrorThatContains('replay store unavailable'));
    }

    public function testReplayProtectionCanBeDisabledPerProfile(): void
    {
        $middleware = $this->middleware(['profiles' => ['api' => ['replay' => false]]]);

        $this->assertSame(200, $middleware->process($this->signedApiRequest(), $this->handler)->getStatusCode());
        $this->assertSame(200, $middleware->process($this->signedApiRequest(), new RecordingHandler())->getStatusCode());
        $this->assertSame([], $this->store->claims);
    }

    public function testBodyLargerThanTheDeclaredSizeLimitIsRefusedBeforeReading(): void
    {
        $request = $this->signedApiRequest();

        $this->assertRejected(
            $this->middleware(['profiles' => ['api' => ['max_body_bytes' => 10]]])->process($request, $this->handler),
            413,
            'body_too_large'
        );
    }

    public function testStreamOfUnknownSizeIsCutOffAtTheLimit(): void
    {
        $request = $this->signedApiRequest()->withBody(new OneShotStream(str_repeat('x', 100)));

        $this->assertRejected(
            $this->middleware(['profiles' => ['api' => ['max_body_bytes' => 10]]])->process($request, $this->handler),
            413,
            'body_too_large'
        );
    }

    public function testOptionsPreflightAndIgnoredPathsPassThrough(): void
    {
        $middleware = $this->middleware();

        $this->assertSame(200, $middleware->process($this->request('OPTIONS', Fixtures::KIPCHAK_URI), $this->handler)->getStatusCode());
        $this->assertSame(200, $middleware->process($this->request('GET', 'https://api.example.com/status'), new RecordingHandler())->getStatusCode());
    }

    public function testOptionsAreCheckedWhenIgnoreOptionsIsOff(): void
    {
        $response = $this->middleware(['ignore_options' => false])->process($this->request('OPTIONS', Fixtures::KIPCHAK_URI), $this->handler);

        $this->assertRejected($response, 401, 'signature_missing');
    }

    public function testPathsWithoutAProfilePassThroughWhenThereIsNoDefault(): void
    {
        $config = Fixtures::config();
        unset($config['default_profile']);
        $middleware = new VerifySignature(new Container(), settings: Settings::fromArray($config), nonceStore: $this->store, clock: $this->clock, logger: new Logger('test', [$this->log]));

        $this->assertSame(200, $middleware->process($this->request('GET', 'https://api.example.com/v1/orders'), $this->handler)->getStatusCode());
        // ...but a webhook path is still protected.
        $this->assertSame(401, $middleware->process($this->request('POST', 'https://api.example.com/webhooks/stripe'), new RecordingHandler())->getStatusCode());
    }

    public function testStripeWebhookIsRoutedByPath(): void
    {
        $request = $this->request('POST', 'https://api.example.com/webhooks/stripe', [
            'Stripe-Signature' => 't=' . Fixtures::NOW . ',v1=' . Fixtures::STRIPE_SIGNATURE,
        ], Fixtures::STRIPE_BODY);

        $response = $this->middleware()->process($request, $this->handler);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('stripe', $this->handler->request->getAttribute(VerifySignature::ATTRIBUTE_PROFILE));
        $this->assertNull($this->handler->request->getAttribute(VerifySignature::ATTRIBUTE_KEY_ID));
    }

    public function testStandardWebhookIsRoutedByPathAndExposesTheMessageId(): void
    {
        $this->clock->timestamp = Fixtures::STANDARD_WEBHOOKS_TIMESTAMP;
        $request = $this->request('POST', 'https://api.example.com/webhooks/standard', [
            'webhook-id' => Fixtures::STANDARD_WEBHOOKS_ID,
            'webhook-timestamp' => (string) Fixtures::STANDARD_WEBHOOKS_TIMESTAMP,
            'webhook-signature' => Fixtures::STANDARD_WEBHOOKS_SIGNATURE,
        ], Fixtures::STANDARD_WEBHOOKS_BODY);

        $this->middleware()->process($request, $this->handler);

        $this->assertSame(Fixtures::STANDARD_WEBHOOKS_ID, $this->handler->request->getAttribute(VerifySignature::ATTRIBUTE_MESSAGE_ID));
    }

    public function testSameReplayIdInDifferentProfilesDoesNotCollide(): void
    {
        $stripeRequest = fn (string $path) => $this->request('POST', "https://api.example.com{$path}", [
            'Stripe-Signature' => 't=' . Fixtures::NOW . ',v1=' . Fixtures::STRIPE_SIGNATURE,
        ], Fixtures::STRIPE_BODY);

        $config = Fixtures::config(['profiles' => ['stripe-eu' => ['scheme' => 'stripe', 'secrets' => [Fixtures::STRIPE_SECRET], 'paths' => ['/webhooks/stripe-eu']]]]);
        $middleware = new VerifySignature(new Container(), settings: Settings::fromArray($config), nonceStore: $this->store, clock: $this->clock, logger: new Logger('test', [$this->log]));

        $this->assertSame(200, $middleware->process($stripeRequest('/webhooks/stripe'), new RecordingHandler())->getStatusCode());
        $this->assertSame(200, $middleware->process($stripeRequest('/webhooks/stripe-eu'), new RecordingHandler())->getStatusCode());
    }

    public function testRouteLevelProfileIgnoresPathMatching(): void
    {
        $request = $this->request('POST', 'https://api.example.com/somewhere/else', [
            'Stripe-Signature' => 't=' . Fixtures::NOW . ',v1=' . Fixtures::STRIPE_SIGNATURE,
        ], Fixtures::STRIPE_BODY);

        $this->assertSame(200, $this->middleware(profile: 'stripe')->process($request, $this->handler)->getStatusCode());
        $this->assertSame(401, $this->middleware()->process($request, new RecordingHandler())->getStatusCode(), 'The default profile expects a kipchak signature');
    }

    public function testUnknownRouteLevelProfileFailsAtConstruction(): void
    {
        $this->expectException(\Kipchak\Middleware\Auth\HMAC\Exceptions\InvalidConfiguration::class);

        $this->middleware(profile: 'missing');
    }

    public function testSignerOutputPassesTheMiddleware(): void
    {
        $request = $this->request('PATCH', 'https://api.example.com/v1/orders/42?expand=items', ['Content-Type' => 'application/json'], '{"status":"paid"}');
        $signed = Signer::kipchak($request, 'client-a', Fixtures::KIPCHAK_ROTATED_SECRET, ['content-type'], timestamp: Fixtures::NOW);

        $this->assertSame(200, $this->middleware()->process($signed, $this->handler)->getStatusCode());
        $this->assertSame('{"status":"paid"}', $this->handler->bodySeen);
    }
}

/**
 * A body that can be read once and cannot be rewound or sized, like a raw socket or php://input on some SAPIs.
 */
final class OneShotStream implements StreamInterface
{
    private int $position = 0;

    public function __construct(private readonly string $contents)
    {
    }

    public function __toString(): string
    {
        return $this->getContents();
    }

    public function close(): void
    {
    }

    public function detach()
    {
        return null;
    }

    public function getSize(): ?int
    {
        return null;
    }

    public function tell(): int
    {
        return $this->position;
    }

    public function eof(): bool
    {
        return $this->position >= strlen($this->contents);
    }

    public function isSeekable(): bool
    {
        return false;
    }

    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        throw new \RuntimeException('Not seekable');
    }

    public function rewind(): void
    {
        throw new \RuntimeException('Not seekable');
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function write(string $string): int
    {
        throw new \RuntimeException('Not writable');
    }

    public function isReadable(): bool
    {
        return true;
    }

    public function read(int $length): string
    {
        $chunk = substr($this->contents, $this->position, $length);
        $this->position += strlen($chunk);

        return $chunk;
    }

    public function getContents(): string
    {
        return $this->read(PHP_INT_MAX);
    }

    public function getMetadata(?string $key = null): mixed
    {
        return $key === null ? [] : null;
    }
}
