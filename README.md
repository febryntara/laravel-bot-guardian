# Laravel Bot Guardian

Lightweight, score-based bot protection middleware for Laravel. Detects and blocks automated attacks using multiple detection layers — from rate limiting hingga behavioral fingerprinting.

---

## Features

- **Score-based detection** — satu violation bukan block; pola yang menentukan
- **12 detection layers** — velocity, honeypot, headers, 404 spam, login brute-force, endpoint rate limit, behavioral pattern, JS challenge, proxy/VPN, distributed attack, slow & low attack, session anomaly
- **Notification on block** — email via Laravel mail + webhook (with HMAC signing)
- **Artisan CLI** — unblock, stats, whitelist, blacklist commands
- **Telemetry log integration** — forward detection events to `laravel-telemetry-logger` (optional companion package)
- **Permanent block for repeat offenders** — recidivist attacker escalation
- **Whitelist / Blacklist** — manual IP control (exact, CIDR, wildcard)
- **Zero config required** — works out of the box with sensible defaults
- **Cache-based, zero database** — lightweight, no migration needed
- **Extensible** — add custom detectors easily
- **Compatible** — Laravel 10, 11, 12 (PHP 8.1+)

---

## Detection Layers

| Detector | What It Checks | Score | Enabled |
|----------|---------------|-------|---------|
| **Velocity** | Request rate dari IP sama (30 req/60s) | +20 | Default |
| **Honeypot** | Akses fake routes (`/wp-login.php`, `/.env`, dll) | +50 | Default |
| **Headers** | Empty UA, known bot UA, missing Accept-Language | +10–25 | Default |
| **404 Spam** | Hit non-existent endpoint berulang (via terminate()) | +30 | Default |
| **Login Attempts** | Brute-force di auth endpoints (5x/5min) | +40 | Manual |
| **Endpoint Rate Limit** | Per-endpoint rate limiting (category-based) | +10–60 | Manual |
| **Behavioral** | No-asset, regular interval, header fingerprint, deep-link | +15–30 | Manual |
| **JS Challenge** | Headless browser / Puppeteer tanpa JS execution | +35–50 | Manual |
| **Proxy / VPN** | Proxy chain anomaly via XFF/Via/Forwarded headers | +10–35 | Manual |
| **Distributed Attack** | Multi-IP botnet fingerprint clustering | +2–30 | Manual |
| **Slow & Low** | Long-window abuse, robotic timing, low endpoint diversity | +20–30 | Manual |
| **Session Anomaly** | Session fixation, hijacking, burst rate | +20–40 | Manual |

**Recidivist Escalation:** Jika IP diblock lebih dari 3x dalam 24 jam → **permanent block** (sampai manual unblock).

**Block duration default:** 1 jam. Permanent block override untuk recidivist.

---

## Installation

```bash
composer require febryntara/laravel-bot-guardian
```

---

## Usage

### Laravel 11+

```php
use Febryntara\LaravelBotGuardian\Middleware\BotGuardianMiddleware;

->withMiddleware(function (Middleware $middleware) {
    $middleware->append(BotGuardianMiddleware::class);
})
```

### Laravel 10

```php
protected $middleware = [
    // ...
    \Febryntara\LaravelBotGuardian\Middleware\BotGuardianMiddleware::class,
];
```

---

## Configuration

Publish config:

```bash
php artisan vendor:publish --provider="Febryntara\LaravelBotGuardian\BotGuardianServiceProvider" --tag="botguardian-config"
```

### Core Settings

```php
'enabled' => true,
'threshold' => 100,         // Score untuk trigger block
'score_decay_window' => 300, // Score reset setelah 5 menit
'block_duration' => 3600,   // 1 jam block
```

### Login Attempt Detector (Brute-Force)

```php
'login_attempts' => [
    'enabled' => true,
    'max_attempts' => 5,
    'time_window' => 300,  // 5 menit
    'score' => 40,
    'routes' => [
        'login', 'auth/login', 'admin/login',
        'api/login', 'api/auth/login', 'authenticate',
    ],
],
```

### Per-Endpoint Rate Limiter

```php
'endpoint_rate_limits' => [
    'enabled' => true,
    'public'     => ['max' => 60,  'window' => 60,  'score' => 10],
    'sensitive'  => ['max' => 10,  'window' => 60,  'score' => 30],
    'critical'   => ['max' => 3,   'window' => 300, 'score' => 60],
    'critical_patterns' => [
        'password', 'payment', 'checkout', 'transfer',
        'api/*/auth', 'reset-password',
    ],
    'endpoints' => [
        // Override per endpoint:
        // '/contact-form' => ['max' => 5, 'window' => 60, 'score' => 50],
    ],
],
```

### Behavioral Pattern Detector

```php
'behavioral' => [
    'enabled' => true,
    'check_no_asset' => true,           // Hanya API, tidak pernah load CSS/JS
    'check_regular_interval' => true,   // Request datang terlalu teratur
    'check_header_fingerprint' => true,  // UA Chrome tapi missing Sec-Fetch-*
    'check_deep_links' => true,         // Langsung deep-link tanpa browse flow
],
```

### Whitelist / Blacklist

```php
'whitelist' => [
    'enabled' => true,
    'ips' => [
        '127.0.0.1',
        '192.168.0.0/24',
        '10.*.1.1',
    ],
],
'blacklist' => [
    'enabled' => true,
    'ips' => [
        // '1.2.3.4',
    ],
],
```

Supported formats: exact IP, CIDR notation (`10.0.0.0/8`), wildcard (`192.168.*`).

### Recidivist Escalation

```php
'recidivist' => [
    'enabled' => true,
    'max_blocks_before_permanent' => 3,
    'count_window' => 86400, // 24 hours
],
```

---

## How It Works

```
Request → Whitelist? → Blacklist? → [Detectors] → Score Accumulator
                                                      ↓
                                              Score >= 100?
                                                      ↓
                                          Recidivist? → Permanent Block
                                          Otherwise   → Temporary Block (1h)
```

1. Semua request melewati middleware
2. Whitelist IP langsung lewat, Blacklist langsung 403
3. Semua detector aktif berjalan paralel
4. Score diakumulasi per IP dalam decay window
5. Jika score >= threshold → IP diblock
6. JikaIP diblock >3x dalam 24 jam → escalate ke **permanent block**
7. Event di-log ke Laravel log

---

## Artisan Commands

```bash
php artisan botguardian:unblock <ip>    # Unblock IP
php artisan botguardian:stats           # Show detection stats
php artisan botguardian:whitelist <ip> # Add IP to whitelist (auto-unblocks if blocked)
php artisan botguardian:blacklist <ip>  # Add IP to blacklist + immediate permanent block
```

Stats command supports `--json` flag for programmatic use:

```bash
php artisan botguardian:stats --json
php artisan botguardian:stats --top=20
```

---

## Notifications

### Email

Uses Laravel's built-in mail (SMTP). Configure in `.env`:

```env
MAIL_MAILER=smtp
MAIL_HOST=smtp.mailtrap.io
MAIL_PORT=2525
MAIL_USERNAME=
MAIL_PASSWORD=
```

Enable in config:

```php
'notifications' => [
    'email' => [
        'enabled' => true,
        'to' => ['admin@example.com', 'security@example.com'],
        'subject_prefix' => '[BotGuardian]',
    ],
],
```

### Webhook

POST JSON payload to any endpoint. Supports HMAC-SHA256 signing.

```php
'notifications' => [
    'webhook' => [
        'enabled' => true,
        'url' => 'https://your-webhook-endpoint.com/bot-alert',
        'secret' => 'your-hmac-secret',     // optional: sets X-BotGuardian-Signature header
        'timeout' => 10,                    // seconds
        'retry' => 3,                       // attempts on failure
        'include_context' => true,           // include full request context
    ],
],
```

**Webhook payload:**

```json
{
  "event": "botguardian.block",
  "type": "temporary",
  "timestamp": "2025-04-16T20:45:00+07:00",
  "ip": "203.0.113.42",
  "total_score": 85,
  "triggered_by": "VelocityDetector",
  "block_duration": 3600,
  "context": {
    "url": "https://example.com/login",
    "user_agent": "python-requests/2.28.0",
    "method": "POST",
    "referer": null,
    "detector_scores": {
      "VelocityDetector": 20,
      "HeaderDetector": 25,
      "HoneypotDetector": 50
    }
  }
}
```

---

## Telemetry Log Integration

Bot Guardian can forward all detection events to the companion package **[laravel-telemetry-logger](https://github.com/febryntara/laravel-telemetry-logger)**.

If you already use `laravel-telemetry-logger` for application logging, enable this integration to have bot events appear in your centralized log pipeline alongside request logs, exceptions, and slow queries.

```php
'telemetry' => [
    'enabled' => true,
],
```

Events forwarded:
- `botguardian.block` — when an IP is blocked (level: `warning`)

No configuration needed on the telemetry side — bot guardian events are sent via `logEvent()` using the same payload format.

---

## Roadmap

- [x] Core detectors (velocity, honeypot, headers, 404 spam)
- [x] Login attempt brute-force detector
- [x] Per-endpoint rate limiting
- [x] Behavioral pattern detector
- [x] Recidivist permanent block escalation
- [x] Whitelist / Blacklist (exact, CIDR, wildcard)
- [x] Atomic cache operations (race condition fix)
- [x] JS challenge / headless browser fingerprinting
- [x] Proxy / VPN detection
- [x] Distributed attack detection
- [x] Slow & low attack detection
- [x] Session anomaly detection
- [x] Artisan commands (unblock, stats, whitelist, blacklist)
- [x] Notification on block (email + webhook)
- [x] Telemetry log integration (`laravel-telemetry-logger` companion)

---

## License

MIT. See [LICENSE](./LICENSE).
