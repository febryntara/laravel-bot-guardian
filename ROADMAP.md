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
- Config: max_requests, time_window, score

### 2. Honeypot Detector ✓
Route palsu: `/wp-login.php`, `/.env`, `/phpMyAdmin`, dll.
- Sekali hit langsung +50 score
- Pattern support untuk sub-routes

### 3. Header Anomaly Detector ✓
- Empty User-Agent = +25
- Known bot UA (`python-requests`, `curl`, `Scrapy`) = +15
- Missing Accept-Language = +10

### 4. NotFoundDetector (404 Spam) ✓
Mendeteksi IP yang sering dapat 404.
- Atomic increment (race condition fix)

### 5. LoginAttemptDetector ✓ [NEW]
Brute-force di auth endpoints.
- Track POST ke login routes
- 5 attempt / 5 menit = +40 score

### 6. EndpointRateLimiter ✓ [NEW]
Per-endpoint rate limiting berbasis kategori.
- public / sensitive / critical
- Per-endpoint override
- Glob pattern support

### 7. BehavioralPatternDetector ✓ [NEW]
Mendeteksi bot berdasarkan cara browsing.
- No-asset pattern (API-only browsing)
- Regular interval detection (robotic timing)
- Header fingerprint mismatch (headless browser detection)
- Deep-link without referer

### 8. RecidivistBlocker ✓ [NEW]
Repeat offender escalation.
- Count block per IP dalam 24h window
- >3 blocks → permanent block (until manual unblock)

### 9. WhitelistChecker ✓ [NEW]
Bypass trusted IPs.
- Exact IP, CIDR notation, wildcard
- Config-based + runtime dynamic

---

## Score System

| Event | Score |
|-------|-------|
| 1 velocity violation | +20 |
| 1 honeypot hit | +50 |
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

**Threshold default: 100**
**Block duration default: 1 jam**
**Permanent block: 3+ blocks dalam 24 jam**

---

## Technical Fixes

### Race Condition Fix ✓
- Semua `Cache::get()` + `Cache::put()` diganti `Cache::increment()`
- Atomic operation — tidak bisa di-spoof dengan concurrent timing

### Decay Window Exploitation Fix ✓
- Recidivist permanent block — attacker tidak bisa wait-out score reset
- Score reset tidak help jika sudah permanent

### Distributed Attack (Partial)
- Behavioral detector membantu deteksi bot yang pakai proxy rotate
- Session fingerprinting masih di roadmap

---

## Remaining: Phase 2

- [ ] BotEvent model + database logging
- [ ] Migration untuk bot_events
- [ ] Artisan commands: unblock, stats, whitelist, blacklist
- [ ] Notification on block (mail/webhook)
- [ ] Distributed attack: session-based fingerprinting (fingerprintJS approach)
- [ ] Dashboard (Blade atau Livewire component)

---

## Remaining: Phase 3

- [ ] JS Challenge (honeypot via JS injection, simplified CAPTCHA)
- [ ] IP reputation integration (external API: AbuseIPDB, IPQualityScore)
- [ ] Geo-blocking (whitelist by country)
- [ ] Rate limiting per user session (not just IP)
- [ ] Challenge-response mode untuk suspect requests

---

## Struktur Paket

```
src/
├── BotGuardianServiceProvider.php
├── RecidivistBlocker.php
├── WhitelistChecker.php
├── Middleware/BotGuardianMiddleware.php
├── Detectors/
│   ├── DetectorInterface.php
│   ├── VelocityDetector.php        ✓ atomic fix
│   ├── HoneypotDetector.php
│   ├── HeaderDetector.php
│   ├── NotFoundDetector.php         ✓ atomic fix
│   ├── LoginAttemptDetector.php     ✓ NEW
│   ├── EndpointRateLimiter.php     ✓ NEW
│   └── BehavioralPatternDetector.php ✓ NEW
├── Scorer/BotScoreCalculator.php   ✓ NEW methods + atomic fix
├── Actions/
│   ├── BlockAction.php              ✓ permanent block
│   └── LogAction.php
└── resources/views/blocked.blade.php

tests/
├── TestCase.php
├── VelocityDetectorTest.php
├── HoneypotDetectorTest.php
├── HeaderDetectorTest.php
├── NotFoundDetectorTest.php
├── BotGuardianMiddlewareTest.php
├── LoginAttemptDetectorTest.php     ✓ NEW
├── BehavioralPatternDetectorTest.php ✓ NEW
└── WhitelistCheckerTest.php         ✓ NEW
```

---

## Prinsip Desain

- **Ringan.** Cache-based by default. Tidak wajib database.
- **Score-based.** Satu violation bukan vonis — pola yang menentukan.
- **Extensible.** Detector baru bisa ditambah tanpa ubah core.
- **Atomic safety.** Tidak ada race condition yang bisa dieksploitasi.
- **Recidivist-aware.** Repeat offender naik ke permanent ban.
- **Zero-config works.** Default masuk akal, bisa langsung pakai.
