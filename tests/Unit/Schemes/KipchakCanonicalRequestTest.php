<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Tests\Unit\Schemes;

use Kipchak\Middleware\Auth\HMAC\Schemes\KipchakCanonicalRequest;
use Kipchak\Middleware\Auth\HMAC\Tests\Unit\Support\Fixtures;
use Kipchak\Middleware\Auth\HMAC\Tests\Unit\Support\Requests;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class KipchakCanonicalRequestTest extends TestCase
{
    use Requests;

    public function testCanonicalStringMatchesTheDocumentedFormat(): void
    {
        $request = $this->request('post', Fixtures::KIPCHAK_URI, ['Content-Type' => 'application/json'], Fixtures::KIPCHAK_BODY);

        $canonical = KipchakCanonicalRequest::build($request, Fixtures::KIPCHAK_BODY, ['content-type'], Fixtures::NOW, Fixtures::KIPCHAK_NONCE, 'client-a');

        $this->assertSame(
            "KIPCHAK-HMAC-V1\n"
            . "1700000000\n"
            . "0123456789abcdef\n"
            . "client-a\n"
            . "POST\n"
            . "/v1/orders\n"
            . "a=0&a=1&b=2&q=hello%20world\n"
            . "content-type:application/json\n"
            . '4d4bbe59c6aad22442cde199a6a8a5f034405fcd78fb5a81c24ef249de1c45f1',
            $canonical
        );
    }

    public function testNoNonceAndNoSignedHeaders(): void
    {
        $request = $this->request('GET', 'https://api.example.com');

        $this->assertSame(
            "KIPCHAK-HMAC-V1\n1700000000\n\nclient-a\nGET\n/\n\n" . hash('sha256', ''),
            KipchakCanonicalRequest::build($request, '', [], Fixtures::NOW, null, 'client-a')
        );
    }

    #[DataProvider('queries')]
    public function testQueryCanonicalisation(string $query, string $expected): void
    {
        $this->assertSame($expected, KipchakCanonicalRequest::query($query));
    }

    public static function queries(): iterable
    {
        yield 'empty' => ['', ''];
        yield 'sorted by name then value' => ['b=2&a=2&a=1', 'a=1&a=2&b=2'];
        yield 'plus is a space' => ['q=a+b', 'q=a%20b'];
        yield 'percent-encoding normalised' => ['q=%7e%41', 'q=~A'];
        yield 'reserved characters encoded' => ['q=a/b?c', 'q=a%2Fb%3Fc'];
        yield 'flag without value' => ['debug&a=1', 'a=1&debug='];
        yield 'empty pieces dropped' => ['a=1&&b=2&', 'a=1&b=2'];
        yield 'byte order, not numeric order' => ['n=10&n=9', 'n=10&n=9'];
        yield 'equals sign inside value' => ['token=a=b', 'token=a%3Db'];
        yield 'unicode' => ['name=%C3%A9', 'name=%C3%A9'];
    }

    public function testHeaderValuesAreTrimmedCollapsedAndJoined(): void
    {
        $this->assertSame('a b,c', KipchakCanonicalRequest::headerValue(["  a \t  b ", 'c']));
        $this->assertSame('', KipchakCanonicalRequest::headerValue([]));
    }

    public function testPathKeepsEncodingAndGainsALeadingSlash(): void
    {
        $this->assertSame('/', KipchakCanonicalRequest::path(''));
        $this->assertSame('/a%20b/c', KipchakCanonicalRequest::path('/a%20b/c'));
        $this->assertSame('/relative', KipchakCanonicalRequest::path('relative'));
    }

    public function testMissingSignedHeaderSignsAsEmpty(): void
    {
        $request = $this->request('GET', 'https://api.example.com/');

        $this->assertStringContainsString("\nx-tenant:\n", KipchakCanonicalRequest::build($request, '', ['x-tenant'], Fixtures::NOW, null, 'k'));
    }
}
