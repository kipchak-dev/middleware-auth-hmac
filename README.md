# HMAC Request Signing Middleware for Kipchak

Verifies signed API requests and webhooks, with replay protection, for Kipchak APIs.

* **Request signing** for your own clients and services: the signature covers the method, path, query, chosen
  headers and body, so a captured signature cannot be reused against another endpoint or with another payload.
* **Webhook verification** for Stripe (`Stripe-Signature`) and any sender that follows the
  [Standard Webhooks](https://www.standardwebhooks.com) spec (Svix, and a growing list of SaaS platforms).
* **Replay protection** that accepts each signed message once, shared by every FrankenPHP worker and host via
  Valkey or Memcached, using atomic writes so simultaneous copies of one request cannot both get through.
* **Key rotation**: several secrets per client or webhook endpoint can be valid at once.
* **A signer** for the sending side, so a Kipchak service can call another, or deliver its own webhooks.

#### Composer Package

`kipchak/middleware-auth-hmac`

## Installation

```bash
composer require kipchak/middleware-auth-hmac
```

For replay protection, install one of the cache drivers too (and initialise it in `drivers/drivers.php`):

| Store | Package | Notes |
|---|---|---|
| `valkey` | `kipchak/driver-valkey` (Enterprise) | Atomic `SET NX`. Recommended. |
| `memcached` | `kipchak/driver-memcached` | Atomic `add`. |
| `filecache` | `kipchak/driver-filecache` | One host only, and check-then-set. For development. |

Then add the middleware in `middlewares/middlewares.php`:

```php
use Kipchak\Middleware\Auth\HMAC\HMAC;

HMAC::initialise($app);
```

and copy [`sample.config.php`](sample.config.php) to `config/kipchak.auth.hmac.php`.

## Configuration

```php
return [
    'enabled' => true,            // register globally; false to attach per route instead (see below)
    'ignore_options' => true,     // let CORS preflight through
    'ignore_paths' => ['/status'],
    'default_profile' => 'api',   // for paths no profile claims; null leaves them unchecked

    'profiles' => [
        'api' => [
            'scheme' => 'kipchak',
            'keys' => ['billing-service' => env('HMAC_BILLING_SERVICE_SECRET', '')],
            'signed_headers' => ['content-type'],
        ],
        'stripe' => [
            'scheme' => 'stripe',
            'secrets' => [env('STRIPE_WEBHOOK_SECRET', '')],
            'paths' => ['/webhooks/stripe'],
        ],
    ],

    'replay' => ['store' => 'valkey', 'pool' => 'cache'],
];
```

### Profiles

A profile is one way of verifying requests. Globally, each request uses the first profile whose `paths` cover it
(a prefix matches itself and everything below it: `/webhooks` covers `/webhooks/stripe`), otherwise
`default_profile`. If neither applies the request passes through unchecked.

| Key | Applies to | Default | Meaning |
|---|---|---|---|
| `scheme` | all | `kipchak` | `kipchak`, `stripe` or `standard-webhooks` |
| `keys` | kipchak | required | key ID => secret, or key ID => list of secrets while rotating. Secrets must be at least 16 bytes; use 32+ random bytes. |
| `secrets` | stripe, standard-webhooks | required | Accepted secrets. Stripe's `whsec_...` is used as-is; Standard Webhooks' `whsec_<base64>` is decoded. |
| `header` | kipchak, stripe | `Kipchak-Signature` / `Stripe-Signature` | Header carrying the signature |
| `header_prefix` | standard-webhooks | `webhook` | Reads `<prefix>-id`, `<prefix>-timestamp`, `<prefix>-signature`. Use `svix` for Svix. |
| `algorithm` | kipchak | `sha256` | `sha256`, `sha384` or `sha512`. Fixed by the server, so clients cannot downgrade it. |
| `signed_headers` | kipchak | `[]` | Headers the signature covers, in order. `content-type` is a good start; add `host` only if no proxy rewrites it. |
| `require_nonce` | kipchak | `true` | Require a nonce, so two identical requests in the same second are both accepted |
| `tolerance` | all | `300` | Seconds either side of the server clock a signature stays valid |
| `paths` | all | `[]` | Path prefixes this profile protects when the middleware is global |
| `max_body_bytes` | all | `1048576` | Larger bodies are refused with 413 before being read in full |
| `replay` | all | `true` | Set `false` to skip replay protection for this profile |

Configuration is validated when the API boots. A missing or short secret, an unknown scheme, or a
`default_profile` that does not exist stops the API from starting rather than accepting requests it cannot verify.

### Replay protection

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Off switch for every profile |
| `store` | `valkey` | `valkey`, `memcached`, `filecache` or `container` |
| `pool` | `cache` | Pool name from the Valkey or Memcached driver config |
| `service` | | For `container`: a service that is a `NonceStore`, a `\Redis`/`\RedisCluster`/Predis/Relay client, a `\Memcached` client, or a PSR-6 pool |
| `prefix` | `kipchak.hmac` | Key prefix; give each API its own if they share a store |
| `fail_open` | `false` | When the store is unreachable: `false` answers 503, `true` accepts the request and logs an error |

Each accepted signature is stored for exactly as long as it could still pass the timestamp check, then expires.
Only signatures that verify are stored, so forged requests cannot fill the store or burn a client's nonces.

The Valkey and Memcached stores are atomic: when 24 processes raced to claim the same signature in the test suite,
exactly one won every time. The `filecache` store and plain PSR-6 pools are check-then-set; in the same race
through a PSR-6 adapter, between 4 and 21 copies got through. Sequential replays are always caught.

If the Valkey connection fails (for example while Valkey restarts), the store reconnects and retries once, so
long-lived FrankenPHP workers recover by themselves once Valkey is back. Keep the pool's `timeout` option short
(the Valkey sample uses 2.5s), since each request during an outage waits for one reconnect attempt.

### Per route instead of globally

Set `'enabled' => false` and attach the handler where you need it, naming the profile:

```php
use Kipchak\Middleware\Auth\HMAC\Handlers\VerifySignature;

$app->post('/webhooks/stripe', [Controllers\Webhooks::class, 'stripe'])
    ->add(new VerifySignature($app->getContainer(), 'stripe'));

$app->group('/v1/internal', function ($group) { /* ... */ })
    ->add(new VerifySignature($app->getContainer(), 'api'));
```

A route-level profile is used regardless of its `paths`.

## What the route receives

Verified requests reach your controller with these request attributes:

| Attribute (constant on `VerifySignature`) | Value |
|---|---|
| `ATTRIBUTE_PROFILE` (`kipchak.hmac.profile`) | Profile name |
| `ATTRIBUTE_KEY_ID` (`kipchak.hmac.key_id`) | Kipchak scheme: the client's key ID |
| `ATTRIBUTE_TIMESTAMP` (`kipchak.hmac.timestamp`) | The signed Unix timestamp |
| `ATTRIBUTE_MESSAGE_ID` (`kipchak.hmac.message_id`) | Standard Webhooks: the sender's message ID |

```php
$client = $request->getAttribute(VerifySignature::ATTRIBUTE_KEY_ID); // e.g. "billing-service"
```

The body is still readable, and Slim's body parsing still works.

Rejected requests get a JSON error with a stable `error` code:

```json
{"code": 401, "status": "UNAUTHENTICATED", "data": {"error": "signature_invalid", "message": "The request signature is invalid."}}
```

| `error` | Status | When |
|---|---|---|
| `signature_missing` | 401 | No signature header(s) |
| `signature_malformed` | 401 | Header present but unparseable, a required part missing, or a nonce that is too short |
| `signature_invalid` | 401 | Wrong signature, or an unknown key ID (deliberately indistinguishable) |
| `timestamp_out_of_tolerance` | 401 | Authentic but outside `tolerance` (check the client's clock) |
| `signature_replayed` | 401 | This exact signed message was already accepted |
| `body_too_large` | 413 | Body over `max_body_bytes` |
| `replay_store_unavailable` | 503 | Replay store down and `fail_open` is false. Safe to retry with a fresh signature. |

The detail behind each rejection (which key ID, how far the clock was off) is logged at `warning` through the
Kipchak logger. Secrets and signatures are never logged.

The `status` comes from kipchak/core's `ErrorStatus`, as kipchak/middleware-error writes it: `UNAUTHENTICATED` for a
401, `PAYLOAD TOO LARGE` for a 413 and `SERVER_ERROR` for a 503. **Upgrading to 1.10:** it requires kipchak/core 3.18,
and those statuses replace `UNAUTHORIZED` and `SERVICE UNAVAILABLE`. Clients should switch on the `error` code, which is
unchanged.

## The kipchak scheme

The client sends one header:

```
Kipchak-Signature: keyId=billing-service,t=1700000000,nonce=3f1c9a7e2b8d4c60a1e5f7b9d2c4e6a8,v1=9735398f...
```

* `keyId`: the client's key ID (A-Z a-z 0-9 . _ ~ -, up to 128 characters)
* `t`: Unix time in seconds
* `nonce`: 16-128 random characters from the same set; a fresh one per request
* `v1`: lower-case hex HMAC of the canonical request below. Send several `v1` values while rotating secrets.

The canonical request is these lines joined with `\n`, with no trailing newline:

```
KIPCHAK-HMAC-V1
<t>
<nonce, or an empty line>
<keyId>
<METHOD in upper case>
<path exactly as sent, still percent-encoded; "/" if empty>
<canonical query>
<one line per signed header, in the profile's order: lower-case-name:value>
<lower-case hex SHA-256 of the raw body (of the empty string if there is none)>
```

* **Canonical query**: split on `&`, drop empty pieces, split each on the first `=` (a missing value is empty),
  treat `+` as a space, percent-decode then re-encode both parts with RFC 3986 rules (`A-Z a-z 0-9 - . _ ~` stay
  as they are, everything else becomes upper-case `%XX`), sort by name then value comparing bytes, and join as
  `name=value` with `&`. An empty query is an empty line.
* **Header values**: trim, collapse runs of whitespace to one space, and join repeated headers with `,`.
  A signed header the request does not carry is signed as `name:` with an empty value.

The scheme name, host and port are not signed, so requests keep verifying behind load balancers and proxies.
Proxies must not rewrite the path, query or body.

### Signing from PHP

```php
use Kipchak\Middleware\Auth\HMAC\Signer;

$request = Signer::kipchak($request, 'billing-service', $secret, ['content-type']);
```

Sign last, once the body and every signed header are final. The signer generates the timestamp and nonce.

### Signing from Python

```python
import hashlib, hmac, os, time
from urllib.parse import quote, unquote, urlsplit

def canonical_query(query):
    pairs = []
    for piece in query.split("&"):
        if not piece:
            continue
        name, _, value = piece.partition("=")
        encode = lambda s: quote(unquote(s.replace("+", "%20")), safe="-._~")
        pairs.append((encode(name), encode(value)))
    pairs.sort(key=lambda pair: (pair[0].encode(), pair[1].encode()))
    return "&".join(f"{name}={value}" for name, value in pairs)

def sign(method, url, headers, body, key_id, secret, signed_headers=("content-type",)):
    parts = urlsplit(url)
    timestamp, nonce = str(int(time.time())), os.urandom(16).hex()
    lowered = {name.lower(): value for name, value in headers.items()}
    lines = ["KIPCHAK-HMAC-V1", timestamp, nonce, key_id, method.upper(),
             parts.path or "/", canonical_query(parts.query)]
    lines += [f"{name}:{' '.join(lowered.get(name, '').split())}" for name in signed_headers]
    lines.append(hashlib.sha256(body).hexdigest())
    signature = hmac.new(secret.encode(), "\n".join(lines).encode(), hashlib.sha256).hexdigest()
    return f"keyId={key_id},t={timestamp},nonce={nonce},v1={signature}"
```

### Signing from a shell

For a request with no query string and `content-type` as the only signed header:

```bash
BODY='{"amount":100}'
TS=$(date +%s)
NONCE=$(openssl rand -hex 16)
BODY_HASH=$(printf '%s' "$BODY" | openssl dgst -sha256 -r | cut -d' ' -f1)
SIG=$(printf 'KIPCHAK-HMAC-V1\n%s\n%s\n%s\n%s\n%s\n\n%s\n%s' \
  "$TS" "$NONCE" "billing-service" "POST" "/v1/orders" "content-type:application/json" "$BODY_HASH" \
  | openssl dgst -sha256 -hmac "$SECRET" -r | cut -d' ' -f1)

curl -X POST https://api.example.com/v1/orders \
  -H 'Content-Type: application/json' \
  -H "Kipchak-Signature: keyId=billing-service,t=$TS,nonce=$NONCE,v1=$SIG" \
  -d "$BODY"
```

## Webhooks

### Stripe

Use the endpoint's signing secret from the Stripe dashboard. While rolling it, list both secrets.

```php
'stripe' => [
    'scheme' => 'stripe',
    'secrets' => [env('STRIPE_WEBHOOK_SECRET', '')],
    'paths' => ['/webhooks/stripe'],
],
```

Any other provider that signs `"{timestamp}.{body}"` with HMAC-SHA256 in a `t=...,v1=...` header can use this
scheme with its own `header`.

### Standard Webhooks and Svix

```php
'inbound' => [
    'scheme' => 'standard-webhooks',
    'secrets' => [env('WEBHOOK_SECRET', '')],  // "whsec_..."
    'paths' => ['/webhooks/inbound'],
    // 'header_prefix' => 'svix',              // for Svix's svix-id / svix-timestamp / svix-signature
],
```

Senders retry failed deliveries with the same message ID and a new timestamp. Replay protection blocks exact
resends but lets retries through, so if your handler must run once per message, deduplicate on
`VerifySignature::ATTRIBUTE_MESSAGE_ID`.

### Sending webhooks from your API

```php
use Kipchak\Middleware\Auth\HMAC\Signer;

$header = Signer::stripe($body, $secret);                          // Stripe-Signature value
$headers = Signer::standardWebhooks($messageId, $body, $secret);   // webhook-id, webhook-timestamp, webhook-signature
```

## Testing

```bash
composer install
vendor/bin/phpunit --testsuite Unit

# Integration tests run against real Valkey and Memcached (and skip without them):
docker run -d --rm --name hmac-valkey -p 56379:6379 valkey/valkey:8-alpine
docker run -d --rm --name hmac-memcached -p 51211:11211 memcached:1.6-alpine
vendor/bin/phpunit
```

The expected signatures in the tests were computed with the `openssl` CLI, and the Standard Webhooks test uses
the spec's published example, so the tests pin the wire format rather than echo the implementation.

## What is a Kipchak Middleware?

Kipchak Middleware is a standard PHP PSR-15 middleware.

Middleware is a component that sits between the request and response of a web application, allowing for interception
and modification of the request and response data. In the context of Kipchak, middleware can be used to handle errors,
authentication, and other cross-cutting concerns that are common across one or more API endpoints.
