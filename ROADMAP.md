# Laravel Bot Guardian — Development Roadmap

Laravel package bot protection dengan pendekatan **score-based detection** — ringan,
extensible, tidak over-engineered.

---

## Konsep Utama

```
Request → Whitelist → Blacklist → [Detectors] → Score Accumulator → Block?
                                                        ↓
                                              Permanent (recidivist)
```

---

## Lapisan Deteksi (DONE)

### 1. Velocity Detector ✓
Mendeteksi request rate dari IP sama dalam window time.
- Atomic increment (race condition fix)
- Warning threshold at 80% before scoring
- Config: max_requests, time_window, score, warning_threshold

### 2. Honeypot Detector ✓
Route palsu: `/wp-login.php`, `/.env`, `/phpMyAdmin`, dll.
- Warning mode: 3 hits → +5, 10 hits → +50 (grace period for typos)
- exclude_routes[] config (per-app customization)
- Pattern support untuk sub-routes

### 3. Header Anomaly Detector ✓
- Empty User-Agent = +25 (was: inverted logic bug fixed)
- Known bot UA (`python-requests`, `curl`, `Scrapy`) = +15
- Missing Accept-Language = +10

### 4. NotFoundDetector (404 Spam) ✓
Mendeteksi IP yang sering dapat 404.
- terminate()-aware: uses actual HTTP 404 status, not route-null heuristic
- pending_block flag: block on NEXT request after threshold exceeded

### 5. LoginAttemptDetector ✓
Brute-force di auth endpoints.
- Track POST ke login routes
- 5 attempt / 5 menit = +40 score

### 6. EndpointRateLimiter ✓
Per-endpoint rate limiting berbasis kategori.
- public / sensitive / critical
- Per-endpoint override
- Glob pattern support

### 7. BehavioralPatternDetector ✓
Mendeteksi bot berdasarkan cara browsing.
- No-asset pattern (API-only browsing)
- Regular interval detection (robotic timing)
- Header fingerprint mismatch (headless browser detection)
- Deep-link without referer
- sort() before diff calculation (chronological ordering)

### 8. RecidivistBlocker ✓
Repeat offender escalation.
- Count block per IP dalam 24h window
- >3 blocks → permanent block (until manual unblock)

### 9. WhitelistChecker ✓
Bypass trusted IPs.
- Exact IP, CIDR notation, wildcard
- Config-based + runtime dynamic

### 10. JsChallengeDetector ✓
JavaScript challenge untuk headless browser / Puppeteer.
- Inject bg_chk signed cookie via terminate()
- Cookie = HMAC-SHA256(ip + timestamp bucket, secret)
- Headless without JS exec: no cookie → +35 score
- Effective for HTML routes; skips api/, _debugbar/, dll.

### 11. ProxyDetector ✓
Proxy / VPN / TOR via HTTP header chain anomaly detection.
- X-Forwarded-For chain analysis (too many hops, private IPs, spoofed chain)
- Via header (explicit proxy indicator)
- X-Real-IP alone (misconfigured proxy)
- Forwarded: RFC 7239 parsing
- Probabilistic — tune per infrastructure

### 12. DistributedAttackDetector ✓
Multi-IP coordinated botnet detection.
- Fingerprint clustering: >10 IPs share same UA+Accept → score
- Endpoint concentration: >20 IPs hit same sensitive endpoint → score
- Catches 1000 IPs × 1 req each where individual velocity passes

### 13. SlowAttackDetector ✓
Slow & low attack (bypass velocity by being slow).
- Long-window total: 24h count > 2000 → score
- Interval entropy: stddev/mean < 10% → robotic timing
- Endpoint diversity: <5 unique endpoints across 20+ requests → script

### 14. SessionAnomalyDetector ✓
Session fixation / hijacking detection.
- Session ID changed but same IP → fixation (+40)
- Same session from >3 distinct IPs → hijacking (+30)
- New session burst >30 req/60s → automated attack (+20)

---

## Score System

| Event | Score |
|-------|-------|
| 1 velocity violation | +20 |
| Velocity warning (80% threshold) | +5 |
| 1 honeypot hit | +50 |
| Honeypot warning (3 hits) | +5 |
| Empty user-agent | +25 |
| Known bot user-agent | +15 |
| Missing Accept-Language | +10 |
| 404 spam | +30 |
| Login brute-force | +40 |
| Endpoint rate limit | +10–60 |
| No-asset pattern | +25 |
| Regular interval | +30 |
| Header fingerprint mismatch | +15–30 |
| Deep-link spam | +20 |
| JS challenge fail (no cookie) | +35–50 |
| Proxy chain anomaly | +10–35 |
| Distributed fingerprint cluster | +2–30 |
| Slow & low (long window) | +20 |
| Slow & low (regular interval) | +25 |
| Slow & low (low diversity) | +30 |
| Session fixation | +40 |
| Session hijacking | +30 |
| Session burst | +20 |

**Threshold default: 100**
**Block duration default: 1 jam**
**Permanent block: 3+ blocks dalam 24 jam**

---

## Technical Fixes (All DONE)
### Race Condition Fix ✓
- Semua `Cache::get()` + `Cache::put()` diganti `Cache::increment()`
- Atomic operation — tidak bisa di-spoof dengan concurrent timing

### Inverted Logic Fix ✓
- HeaderDetector: `!empty(bool)` → bare boolean check

### TerminableMiddleware Pattern ✓
- terminate() untuk post-response 404 detection
- pending_block flag untuk block-on-next-request pattern
- JS challenge cookie injection via terminate()

### BehavioralDetector Sort Fix ✓
- sort() sebelum diff calculation (entries bisa dalam urutan apapun)

### SlowAttackDetector Test Fix ✓
- checkSlowInterval() accepts optional $intervals array for testing
- Intervals sorted chronologically before diff calculation

---

## Remaining: Phase 2

- [ ] BotEvent model + database logging
- [ ] Migration untuk bot_events
- [ ] Artisan commands: unblock, stats, whitelist, blacklist
- [ ] Notification on block (mail/webhook)
- [ ] Dashboard (Blade atau Livewire component)
- [ ] Advanced fingerprinting (canvas/WebGL noise fingerprinting)

---

## Remaining: Phase 3

- [ ] IP reputation integration (external API: AbuseIPDB, IPQualityScore)
- [ ] Geo-blocking (MaxMind GeoLite2 database integration)
- [ ] Rate limiting per user session (not just IP)
- [ ] Challenge-response mode untuk suspect requests
- [ ] Cloudflare / Sucuri / Incapsula integration (trust proxy headers)

---

## Struktur Paket

```
src/
├── BotGuardianServiceProvider.php
├── RecidivistBlocker.php
├── WhitelistChecker.php
├── Middleware/BotGuardianMiddleware.php   ✓ terminate() + pending_block + JS cookie inject
├── Detectors/
│   ├── DetectorInterface.php
│   ├── VelocityDetector.php              ✓ atomic + warning threshold
│   ├── HoneypotDetector.php              ✓ exclude_routes + warning mode
│   ├── HeaderDetector.php                ✓ fixed !empty(bool) logic inversion
│   ├── NotFoundDetector.php              ✓ terminate-aware (stateless detect)
│   ├── LoginAttemptDetector.php          ✓
│   ├── EndpointRateLimiter.php           ✓
│   ├── BehavioralPatternDetector.php     ✓ + sort fix
│   ├── JsChallengeDetector.php           ✓
│   ├── ProxyDetector.php                 ✓
│   ├── DistributedAttackDetector.php     ✓
│   ├── SlowAttackDetector.php            ✓
│   └── SessionAnomalyDetector.php       ✓
├── Scorer/BotScoreCalculator.php        ✓ increment() returns total + increment404()
├── Actions/
│   ├── BlockAction.php                   ✓ permanent block
│   └── LogAction.php
└── resources/views/blocked.blade.php

tests/ (79 tests, 112 assertions)
├── VelocityDetectorTest.php
├── HoneypotDetectorTest.php
├── HeaderDetectorTest.php
├── NotFoundDetectorTest.php
├── BotGuardianMiddlewareTest.php
├── LoginAttemptDetectorTest.php
├── BehavioralPatternDetectorTest.php
├── WhitelistCheckerTest.php
├── EndpointRateLimiterTest.php
├── RecidivistBlockerTest.php
├── JsChallengeDetectorTest.php          ✓
├── ProxyDetectorTest.php                ✓
├── DistributedAttackDetectorTest.php    ✓
├── SlowAttackDetectorTest.php           ✓
└── SessionAnomalyDetectorTest.php       ✓
```

---

## Prinsip Desain

- **Ringan.** Cache-based by default. Tidak wajib database.
- **Score-based.** Satu violation bukan vonis — pola yang menentukan.
- **Extensible.** Detector baru bisa ditambah tanpa ubah core.
- **Atomic safety.** Tidak ada race condition yang bisa dieksploitasi.
- **Recidivist-aware.** Repeat offender naik ke permanent ban.
- **Zero-config works.** Default masuk akal, bisa langsung pakai.
