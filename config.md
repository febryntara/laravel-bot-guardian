# Konfigurasi Bot Guardian

Dokumentasi lengkap setiap key di `config/botguardian.php`. Baca [README.md](./README.md) untuk panduan install dan overview.

---

## Core Settings

### `enabled`
```php
'enabled' => true,
```
**Tipe:** boolean | **Default:** `true`

Mengaktifkan atau menonaktifkan seluruh Bot Guardian. Jika `false`, semua request dilewati tanpa pengecekan — berguna saat maintenance atau debugging.

---

### `threshold`
```php
'threshold' => 100,
```
**Tipe:** integer | **Default:** `100`

Total score minimum untuk memicu block. Jika akumulasi score dari semua detector >= threshold, IP akan diblokir.

| Threshold | Efek |
|-----------|------|
| Rendah (30–50) | Sensitif, banyak false positive, proteksi agresif |
| Sedang (80–100) | Balanced, false positive minimal |
| Tinggi (150+) | Toleran, hanya block serangan jelas |

**Rekomendasi:** Mulai dari default (100), turunkan jika bot attack masih lolos, naikkan jika banyak user legit terblokir.

---

### `score_decay_window`
```php
'score_decay_window' => 300,
```
**Tipe:** integer (detik) | **Default:** `300` (5 menit)

Score akumulasi bersifat sementara. Setelah `score_decay_window` detik tanpa violations tambahan, score di-reset ke 0.

| Nilai | Efek |
|-------|------|
| Pendek (60–120) | Score cepat reset, cocok untuk burst attack detection |
| Default (300) | Balanced, 5 menit window |
| Panjang (600+) | Score bertahan lama, berguna untuk slow attack pattern |

---

### `block_duration`
```php
'block_duration' => 3600,
```
**Tipe:** integer (detik) | **Default:** `3600` (1 jam)

Durasi block sementara. Permanent block terjadi lewat mekanisme recidivist, bukan via setting ini.

| Nilai | Efek |
|-------|------|
| Pendek (300–600) | Block cepat expired, tapi attacker bisa retry cepat |
| Default (3600) | 1 jam block, cukup untuk stop serangan burst |
| Panjang (7200+) | Block bertahan lama, tapi susah untuk unblock legit user |

---

### `block_view`
```php
'block_view' => 'botguardian::blocked',
```
**Tipe:** string (blade view path) | **Default:** `botguardian::blocked`

Blade view yang ditampilkan saat IP terblokir. Customize dengan publish ke `resources/views/vendor/botguardian/blocked.blade.php`.

---

## Velocity Detector

Mendeteksi request rate tinggi dari IP yang sama.

```php
'velocity' => [
    'enabled' => true,
    'max_requests' => 30,
    'time_window' => 60,
    'score' => 20,
    'warning_threshold' => 0.8,
],
```

| Key | Default | Penjelasan |
|-----|---------|-----------|
| `enabled` | `true` | Aktif/nonaktif detector |
| `max_requests` | `30` | Maksimum request per `time_window` detik |
| `time_window` | `60` | Window durasi penghitungan (detik) |
| `score` | `20` | Score yang ditambahkan jika exceeded |
| `warning_threshold` | `0.8` | Log warning saat mencapai 80% limit (24 req) |

**ON:** Mendeteksi scraper, crawler, automated script yang membanjiri server. Normal browsing user tidak akan terpengaruh (rata-rata 1–5 req/menit).

**OFF:** Tidak ada proteksi terhadap request flooding. Attacker bisa mengirim ribuan request tanpa terdeteksi.

---

## Honeypot Detector

Menarik bot yang mengakses fake routes — endpoint yang tidak ada di aplikasi legitimate.

```php
'honeypot' => [
    'enabled' => true,
    'routes' => [
        '/wp-admin',
        '/wp-login.php',
        '/.env',
        // ...
    ],
    'score' => 50,
],
```

| Key | Default | Penjelasan |
|-----|---------|-----------|
| `enabled` | `true` | Aktif/nonaktif detector |
| `routes` | `array` | Daftar fake routes yang diawasi |
| `score` | `50` | Score untuk setiap akses ke honeypot route |

**ON:** Mendeteksi scanner bot yang mencari vulnerability (wp-admin, .env, phpMyAdmin, shell.php). Bot otomatis ter-flag berat (+50 score).

**OFF:** Scanner bisa扫描 aplikasi tanpa terdeteksi. Namun jika semua honeypot routes adalah public-facing fake routes, nonaktifkan jika ingin menghindari false positive dari crawler legitimate.

**Catatan:** Honeypot routes tidak harus benar-benar ada di route aplikasi. Cukup declare di config, dan akses ke path tersebut langsung terdeteksi.

---

## Header Detector

Validasi request header untuk mendeteksi bot yang tidak mengikuti browser normal.

```php
'headers' => [
    'enabled' => true,
    'block_empty_user_agent' => true,
    'empty_user_agent_score' => 25,
    'block_known_bots' => true,
    'known_bot_patterns' => ['python-requests', 'curl/', ...],
    'known_bot_score' => 15,
    'missing_accept_language_score' => 10,
],
```

| Key | Default | Penjelasan |
|-----|---------|-----------|
| `block_empty_user_agent` | `true` | Block jika UA kosong |
| `empty_user_agent_score` | `25` | Score untuk empty UA |
| `block_known_bots` | `true` | Flag known bot UA patterns |
| `known_bot_patterns` | `array` | Pattern yang dianggap bot (case-insensitive) |
| `known_bot_score` | `15` | Score untuk known bot UA |
| `missing_accept_language_score` | `10` | Score jika header Accept-Language hilang |

**ON:** Menangkis bot script yang tidak设 UA atau menggunakan known library UA (python-requests, curl, scrapy).

**OFF:** Request tanpa UA atau dengan bot UA tidak terdeteksi. User dengan browser normal tidak terpengaruh regardless.

---

## 404 Spam Detector

Mendeteksi IP yang mengakses banyak non-existent endpoints.

```php
'not_found_spam' => [
    'enabled' => true,
    'max_hits' => 10,
    'time_window' => 60,
    'score' => 30,
],
```

| Key | Default | Penjelasan |
|-----|---------|-----------|
| `enabled` | `true` | Aktif/nonaktif |
| `max_hits` | `10` | Maks 404 per window |
| `time_window` | `60` | Window detection |
| `score` | `30` | Score per violation |

**ON:** Mendeteksi dirbuster/fuzzer bot yang mencoba cari file sensitif atau vulnerability. Juga menangkap broken link crawling yang agresif.

**OFF:** Tidak ada proteksi terhadap directory enumeration dan brute-force endpoint discovery.

---

## Login Attempt Detector

Mendeteksi brute-force attack di auth endpoints.

```php
'login_attempts' => [
    'enabled' => false,
    'max_attempts' => 5,
    'time_window' => 300,
    'score' => 40,
    'routes' => ['login', 'auth/login', ...],
],
```

| Key | Default | Penjelasan |
|-----|---------|-----------|
| `enabled` | `false` | Manual enable |
| `max_attempts` | `5` | Maks attempt per window |
| `time_window` | `300` | 5 menit window |
| `score` | `40` | Score tinggi karena sensitive area |
| `routes` | `array` | Route patterns untuk diawasi |

**ON:** Melindungi endpoint login dari brute-force. Jika ada 5 failed login attempts dalam 5 menit, attacker terflag (+40 score).

**OFF:** Tidak ada proteksi terhadap login brute-force. Perlu integrator mengaktifkan secara manual karena aplikasi tanpa auth tidak membutuhkan ini.

**Pro-tip:** Aktifkan jika aplikasi memiliki fitur login/register/reset password.


---

## Endpoint Rate Limiter

Rate limit berbeda untuk setiap kategori endpoint.

```php
'endpoint_rate_limits' => [
    'enabled' => false,
    'public'     => ['max' => 60,  'window' => 60,  'score' => 10],
    'sensitive'  => ['max' => 10,  'window' => 60,  'score' => 30],
    'critical'   => ['max' => 3,   'window' => 300, 'score' => 60],
    'critical_patterns' => ['password', 'payment', 'checkout', ...],
    'endpoints' => [],
],
```

| Category | Default Limit | Window | Score | Contoh Endpoint |
|----------|--------------|--------|-------|----------------|
| `public` | 60 req | 60s | +10 | `/`, `/about`, `/blog` |
| `sensitive` | 10 req | 60s | +30 | `/api/data`, `/search` |
| `critical` | 3 req | 300s | +60 | `/payment`, `/checkout` |

Endpoint masuk kategori `critical` jika path-nya matching salah satu pattern di `critical_patterns`.

| Key | Default | Penjelasan |
|-----|---------|-----------|
| `enabled` | `false` | Manual enable |
| `public` / `sensitive` / `critical` | `array` | Limit per kategori |
| `critical_patterns` | `array` | Route patterns untuk critical category |
| `endpoints` | `array` | Override limit per endpoint spesifik |

**ON:** Proteksi bertingkat berdasarkan sensitivitas endpoint. API abuse, scraping, payment fraud bisa dicegah.

**OFF:** Semua endpoint mendapat proteksi yang sama (dari detector lain). Tidak ada granular rate control.

**Catatan:** Untuk override per endpoint:
```php
'endpoints' => [
    '/api/submit-form' => ['max' => 5, 'window' => 60, 'score' => 50],
],
```

---

## Behavioral Pattern Detector

Mendeteksi pola perilaku yang tidak wajar dibanding browser manusia.

```php
'behavioral' => [
    'enabled' => false,
    'window' => 120,
    'max_score' => 50,
    'check_no_asset' => true,
    'no_asset_min_requests' => 10,
    'no_asset_ratio_threshold' => 0.1,
    'no_asset_score' => 25,
    'check_regular_interval' => true,
    'interval_stddev_threshold' => 0.05,
    'regular_interval_score' => 30,
    'check_header_fingerprint' => true,
    'missing_sec_fetch_score' => 15,
    'missing_accept_score' => 5,
    'inconsistent_accept_score' => 10,
    'fingerprint_mismatch_score' => 15,
    'check_deep_links' => true,
    'min_deep_links' => 5,
    'deep_link_score' => 20,
],
```

| Check | Penjelasan | Deteksi |
|-------|-----------|---------|
| `no_asset` | Tidak pernah request CSS/JS/image | API-only scraper bot |
| `regular_interval` | Request timing terlalu uniform (stddev < 0.05s) | Automated script dengan sleep() |
| `header_fingerprint` | UA Chrome tapi missing Sec-Fetch-* headers | Headless browser spoofing |
| `deep_links` | Langsung akses deep URL tanpa browse flow | Scraping bot, spam bot |

| Key | Default | Penjelasan |
|-----|---------|-----------|
| `enabled` | `false` | Manual enable |
| `window` | `120` | Sample window untuk analisis (detik) |
| `max_score` | `50` | Score maksimum untuk behavioral violations |
| Per-check configs | variabel | Threshold dan score per check |

**ON:** Mendeteksi sophisticated bot yang lolos dari detector lain. Sangat efektif untuk bot yang coba tiru browser normal tapi gagal di细节 behavioral.

**OFF:** Tidak ada proteksi terhadap bot yang behave mirip browser. Detector lain (velocity, honeypot) tetap berfungsi.

**Kelebihan:** Mendeteksi bot tanpa signature-based detection — tidak bisa di-bypass dengan mengubah UA atau headers.

**Kekurangan:** Membrane false positive untuk legitimate API clients (non-browser API consumers). **Jangan aktifkan jika aplikasi serving API-only clients.**

---

## JS Challenge Detector

Menyisipkan inline JavaScript challenge untuk mendeteksi headless browser.

```php
'js_challenge' => [
    'enabled' => false,
    'secret' => 'botguardian-challenge-secret',
    'token_validity' => 300,
    'missing_token_score' => 35,
    'invalid_token_score' => 50,
    'skip_prefixes' => ['api/', '_debugbar/', 'telescope/', ...],
],
```

| Key | Default | Penjelasan |
|-----|---------|-----------|
| `enabled` | `false` | Manual enable |
| `secret` | `string` | Secret key untuk token generation. **HARUS diubah di production!** |
| `token_validity` | `300` | Token valid untuk 5 menit |
| `missing_token_score` | `35` | Jika cookie challenge tidak ada |
| `invalid_token_score` | `50` | Jika token tidak valid |
| `skip_prefixes` | `array` | Route prefixes yang discope dari challenge |

**Mekanisme:**
1. User pertama kali visit → middleware inject inline `<script>` yang set cookie `botguardian_js_challenge=VALID_token`
2. Browser legitimate menjalankan script → cookie ter-set
3. Request berikutnya → cookie dibaca, challenge bypassed
4. Headless browser (Puppeteer/Playwright) yang tidak dieksekusi JS → tidak punya cookie → terdeteksi (+35–50 score)

**ON:** Mendeteksi Puppeteer, Playwright, Selenium, PhantomJS, dan headless Chrome. Sangat efektif untuk bot yang automate browser actions.

**OFF:** Tidak ada proteksi terhadap headless browser attacks. User dengan browser normal tidak terpengaruh.

**Kelebihan:** Signature-based bypass tidak mungkin — JS harus benar-benar dieksekusi oleh browser.

**Kekurangan:**
- Tidak bisa digunakan untuk API-only apps (karena API client tidak execute JS)
- Menambah latency ~1-2ms per first request per session
- Headless browser yang dikonfigurasi untuk handle cookies masih bisa bypass

**Catatan:** Set `secret` ke value random unik di production:
```php
'secret' => env('BOTGUARDIAN_JS_SECRET', Str::random(32)),
```

---

## Proxy / VPN Detector

Mendeteksi proxy chain anomaly via header analysis.

```php
'proxy' => [
    'enabled' => false,
    'max_xff_hops' => 3,
    'xff_too_many_hops_score' => 20,
    'xff_private_ip_score' => 30,
    'xff_without_xri_score' => 10,
    'xff_spoofed_chain_score' => 35,
    'xff_matches_direct_ip_score' => 25,
    'via_header_score' => 25,
    'xri_alone_score' => 15,
    'xri_private_ip_score' => 30,
    'forwarded_private_score' => 30,
    'max_score' => 50,
],
```

| Key | Default | Penjelasan |
|-----|---------|-----------|
| `enabled` | `false` | Manual enable |
| `max_xff_hops` | `3` | Maksimum proxy hops di X-Forwarded-For |
| Per-indicator scores | variabel | Score per anomaly pattern |

**Indicator yang dideteksi:**
- `X-Forwarded-For` tanpa `X-Real-IP` — corporate proxy biasanya kirim keduanya
- Private IP di header (`10.x`, `172.16.x`, `192.168.x`) — spoofing attempt
- Terlalu banyak hops (>3) — recursive proxy abuse
- `Via` header tanpa proxy legitimate
- Proto mismatch (`http` forwarded tapi koneksi `https`)

**ON:** Mendeteksi request dari VPN, proxy, atau spoofed IP. Berguna untuk keamanan tambahan di aplikasi sensitif.

**OFF:** Tidak ada proteksi terhadap attacker yang menggunakan VPN/proxy.

**Kelebihan:** Zero-latency — hanya analisis header, tidak ada request tambahan.

**Kekurangan:**
- False positive tinggi untuk user di belakang corporate CDN/proxy (Cloudflare, Fastly, dll)
- VPN user legitimate tidak bisa dibedakan dari attacker
- Attacker dengan residential proxy masih bisa lolos

**Rekomendasi:** Aktifkan hanya jika kamu paham network infrastructure. Jika ada Cloudflare di depan, pertimbangkan untuk disable atau tune thresholds.


---

## Distributed Attack Detector

Mendeteksi coordinated botnet attack — banyak IP berbeda tapi fingerprint sama (bot script yang rotate IP).

```php
'distributed' => [
    'enabled' => false,
    'window' => 120,
    'ips_per_fingerprint' => 10,
    'score_per_ip' => 2,
    'max_fingerprint_score' => 30,
    'endpoint_window' => 300,
    'ips_per_endpoint' => 20,
    'score_per_ip' => 1,
    'max_endpoint_score' => 30,
    'sensitive_patterns' => ['login', 'auth', 'password', ...],
    'max_score' => 60,
],
```

| Key | Default | Penjelasan |
|-----|---------|-----------|
| `enabled` | `false` | Manual enable |
| `window` | `120` | Window untuk fingerprint clustering |
| `ips_per_fingerprint` | `10` | Flag jika >10 IPs pakai fingerprint sama |
| `score_per_ip` | `2` | Score per IP额外 dari fingerprint cluster |
| `endpoint_window` | `300` | Window untuk endpoint diversity check |
| `ips_per_endpoint` | `20` | Flag jika >20 IPs hit sensitive endpoint |
| `sensitive_patterns` | `array` | Endpoint patterns yang diawasi |

**Mekanisme:**
1. Build fingerprint dari `User-Agent + Accept + Accept-Language` header
2. Track: "fingerprint X sudah menyentuh berapa IP berbeda?"
3. Jika >10 IPs pakai fingerprint sama dalam 2 menit → distributed attack suspected

**ON:** Mendeteksi botnet yang pakai script rotate IP (via proxy pool) tapi fingerprint tidak berubah. Ataubot yang menyerang sensitive endpoint (login, auth) dari banyak IP berbeda.

**OFF:** Tidak ada proteksi terhadap distributed attack yang coordinate dari banyak IP.

**Kelebihan:** Tidak tergantung pada rate per-IP — bisa mendeteksi attack yang 1 req/IP dari 1000 IPs berbeda.

**Kekurangan:** Jika attacker rotate IP dan fingerprint bersamaan, tidak terdeteksi. Membutuhkan memory untuk tracking fingerprint-to-IP mapping.

---

## Slow & Low Attack Detector

Mendeteksi attacker yang deliberately slow untuk lolos dari velocity detection.

```php
'slow_attack' => [
    'enabled' => false,
    'long_window' => 86400,
    'daily_request_limit' => 2000,
    'long_window_score' => 20,
    'interval_window' => 600,
    'interval_coef_threshold' => 0.1,
    'regular_interval_score' => 25,
    'diversity_window' => 3600,
    'min_requests_for_diversity' => 20,
    'min_unique_endpoints' => 5,
    'low_diversity_score' => 30,
    'max_score' => 60,
],
```

| Check | Penjelasan | Deteksi |
|-------|-----------|---------|
| `long_window` | Total request per 24h | Abuser yang perlahan tapi konsisten |
| `interval` | stddev/mean interval < 10% = terlalu teratur | Script dengan fixed `sleep()` |
| `diversity` | < 5 unique endpoints dari 20+ requests | Targeted scraping / scraping template |

| Key | Default | Penjelasan |
|-----|---------|-----------|
| `enabled` | `false` | Manual enable |
| `long_window` | `86400` | 24 jam tracking window |
| `daily_request_limit` | `2000` | Flag jika >2000 req/24h |
| `interval_coef_threshold` | `0.1` | stddev/mean < 10% = suspicious |
| `diversity_window` | `3600` | 1 jam untuk diversity check |

**ON:** Mendeteksi slow bot yang tidur 30 detik antar request selama berjam-jam — lolos dari velocity (30 req/min) tapi tetap abnormal.

**OFF:** Slow attack tidak terdeteksi selama rate stay di bawah threshold detector lain.

**Kelebihan:** Satu-satunya detector yang mendeteksi attack dengan interval >1 menit.

**Kekurangan:** Cache TTL panjang (24h untuk long window) — konsumsi memory lebih tinggi. False positive possible untuk scheduled cron jobs atau monitoring services yang regular.

---

## Session Anomaly Detector

Mendeteksi session fixation dan hijacking attacks.

```php
'session' => [
    'enabled' => false,
    'max_ips_per_session' => 3,
    'session_fixation_score' => 40,
    'session_hijack_score' => 30,
    'burst_window' => 60,
    'max_burst_requests' => 30,
    'burst_score' => 20,
    'session_tracking_window' => 86400,
    'max_score' => 50,
],
```

| Key | Default | Penjelasan |
|-----|---------|-----------|
| `enabled` | `false` | Manual enable |
| `max_ips_per_session` | `3` | Flag jika >3 IPs pakai session sama |
| `session_fixation_score` | `40` | Score untuk session ID in URL |
| `session_hijack_score` | `30` | Score untuk session hijacking |
| `burst_window` | `60` | 1 menit window |
| `max_burst_requests` | `30` | Flag jika >30 req/menit via session |
| `session_tracking_window` | `86400` | 24h tracking |

**Attack yang dideteksi:**

**Session Fixation:** Attacker membuat session ID, mengirim ke victim, victim login dengan session tersebut → attacker langsung punya akses authenticated session.

**Session Hijacking:** Attacker mencuri session cookies, menggunakan dari IP berbeda → mendeteksi multi-IP session usage.

**Session Burst:** Automated script yang pakai stolen session cookies — kecepatan tinggi tapi berasal dari session, bukan IP baru.

**ON:** Mendeteksi session-based attacks. Penting untuk aplikasi dengan user accounts.

**OFF:** Session attack tidak terdeteksi. Attacker yang gunakan stolen session tetap bisa access tanpa terdeteksi.

**Catatan:** Membutuhkan Laravel session middleware berjalan sebelum Bot Guardian. Jika pakai custom session driver, pastikan header tracking works.

**Kelebihan:** Mendeteksi attack yang tidak bisa dideteksi dari IP perspective — attacker pakai stolen valid session dari IP berbeda.

**Kekurangan:** Membutuhkan session middleware. Tidak efektif untuk aplikasi stateless/API-only.

---

## Recidivist Tracker

Automatic escalation ke permanent block untuk repeat offenders.

```php
'recidivist' => [
    'enabled' => true,
    'max_blocks_before_permanent' => 3,
    'count_window' => 86400,
],
```

| Key | Default | Penjelasan |
|-----|---------|-----------|
| `enabled` | `true` | Aktif/nonaktif |
| `max_blocks_before_permanent` | `3` | Block >3x dalam window → permanent |
| `count_window` | `86400` | 24 jam reset window |

**Mekanisme:**
1. IP kena temporary block (via threshold)
2. Recidivist tracker increment counter
3. Jika IP kena block lagi dalam 24h window → counter naik
4. Counter > 3 → escalate ke **permanent block** (Cache::forever)
5. Permanent block hanya bisa di-unblock via `botguardian:unblock`

**ON:** Repeat attacker otomatis di-escalate ke permanent block. Tidak perlu manual intervention untuk bot yang berulang kali menyerang.

**OFF:** Attacker bisa terus retry setiap block expired tanpa escalation.

---

## Whitelist / Blacklist

Manual IP control dengan pattern matching.

```php
'whitelist' => [
    'enabled' => false,
    'ips' => ['127.0.0.1', '192.168.0.0/24', '10.*.1.1'],
],
'blacklist' => [
    'enabled' => false,
    'ips' => ['1.2.3.4'],
],
```

| Format | Contoh | Match |
|--------|--------|-------|
| Exact IP | `192.168.1.100` | Hanya IP itu |
| CIDR | `10.0.0.0/8` | Semua IP di range |
| Wildcard | `192.168.*` atau `192.168.1.*` | Pattern match |

| List | Efek |
|------|------|
| **Whitelist ON** | IP di whitelist langsung bypass semua detector |
| **Blacklist ON** | IP di blacklist langsung 403 tanpa detector check |
| **Both ON** | Whitelist checked first → blacklist second |

**ON Whitelist:** Lindungi internal services, monitoring IPs, admin machines dari false positive blocking.

**ON Blacklist:** Block known malicious IPs secara permanen tanpa harus tunggu mereka trigger detector.

**CLI Usage:**
```bash
php artisan botguardian:whitelist 192.168.1.50
php artisan botguardian:blacklist 1.2.3.4
```


---

## Notifications

Kirim alert saat IP diblokir — bisa email, webhook, atau keduanya sekaligus.

### Email Notification

```php
'notifications' => [
    'email' => [
        'enabled' => false,
        'to' => ['admin@example.com'],
        'subject_prefix' => '[BotGuardian]',
    ],
],
```

| Key | Default | Penjelasan |
|-----|---------|-----------|
| `enabled` | `false` | Toggle email notification |
| `to` | `array` | Daftar recipient email |
| `subject_prefix` | `[BotGuardian]` | Prefix subject line |

**Config SMTP:** Pakai konfigurasi mail `.env` yang sudah ada:
```env
MAIL_MAILER=smtp
MAIL_HOST=smtp.mailtrap.io
MAIL_PORT=2525
MAIL_USERNAME=
MAIL_PASSWORD=
```

**Email yang dikirim:**
```
⚠️ BOT BLOCKED — IP: 203.0.113.42
IP Address : 203.0.113.42
Total Score: 85
Triggered  : VelocityDetector
Blocked At : 2025-04-16 20:45:00

--- Request Context ---
URL        : https://example.com/login
User-Agent: python-requests/2.28.0
Method     : POST

--- Detector Breakdown ---
  VelocityDetector: 20
  HeaderDetector: 25
  HoneypotDetector: 50
```

**ON:** Team bisa dapat alert real-time saat bot attack terjadi. Berguna untuk incident response dan monitoring.

**OFF:** Tidak ada notifikasi. Block event hanya masuk Laravel log.

---

### Webhook Notification

```php
'notifications' => [
    'webhook' => [
        'enabled' => false,
        'url' => null,
        'secret' => null,
        'timeout' => 10,
        'retry' => 3,
        'include_context' => true,
    ],
],
```

| Key | Default | Penjelasan |
|-----|---------|-----------|
| `enabled` | `false` | Toggle webhook notification |
| `url` | `null` | Target endpoint URL |
| `secret` | `null` | HMAC-SHA256 signing key (opsional) |
| `timeout` | `10` | Request timeout (detik) |
| `retry` | `3` | Retry attempts saat gagal |
| `include_context` | `true` | Include full request context |

**Payload:**
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

**HMAC Signature (jika secret diset):**
Header `X-BotGuardian-Signature` berisi:
```
sha256=<HMAC-SHA256 of JSON payload using secret>
```

**Integrasi contoh:**

Slack:
```
POST https://hooks.slack.com/services/xxx/yyy/zzz
```

Pipedream / n8n / Make webhook:
```
POST https://hook.pipedream.com/...
```

**ON:** Alert bisa diarahkan ke Slack, Discord, PagerDuty, email via webhook relay, atau custom endpoint untuk automated response.

**OFF:** Tidak ada webhook alert. Semua block event lokal.

---

## Telemetry Integration

Forward detection events ke companion package `laravel-telemetry-logger`.

```php
'telemetry' => [
    'enabled' => false,
],
```

| Key | Default | Penjelasan |
|-----|---------|-----------|
| `enabled` | `false` | Toggle telemetry forwarding |

**Events yang diforward:**
- `botguardian.block` — saat IP diblokir (level: `warning`)

**Format payload** (kompatibel dengan `logEvent()` telemetry):
```php
[
    'event' => 'botguardian.block',
    'data' => [
        'ip' => '203.0.113.42',
        'permanent' => false,
        'score' => 85,
        'triggered_by' => 'VelocityDetector',
    ],
    'level' => 'warning',
]
```

**Persyaratan:**
- Package `febryntara/laravel-telemetry-logger` sudah ter-install
- `telemetry-logger.enabled = true` di config telemetry-logger.php

**ON:** Bot events muncul di centralized log pipeline yang sama dengan request logs, exceptions, slow queries — dari satu dashboard.

**OFF:** Bot events hanya di local Laravel log. Tidak terintegrasi dengan telemetry system.

**Catatan:** Tidak ada coupling antara kedua package. Bot Guardian beroperasi normal jika telemetry tidak tersedia — hanya silent skip.

---

## Logging

```php
'log_enabled' => true,
```

| Value | Efek |
|-------|------|
| `true` | Semua detection + block events masuk Laravel log (`storage/logs/laravel.log`) |
| `false` | Tidak ada logging sama sekali |

Log entry contoh:
```
[2025-04-16 20:45:00] local.WARNING: Bot Guardian: BLOCKED — IP: 203.0.113.42 — Total Score: 85
```

**Catatan:** Ini logging ke file local, bukan database. Untuk centralized logging yang lebih advanced, aktifkan `telemetry` integration.

---

## Ringkasan: ON vs OFF

| Detector | ON Benefit | OFF Impact |
|----------|-----------|-----------|
| **Velocity** | Mencegah request flooding | Risk request flooding |
| **Honeypot** | Block scanner bot | Scanner bisa scan bebas |
| **Headers** | Block UA spoofing | Bot dengan fake UA tidak terdeteksi |
| **404 Spam** | Block dirbuster | Directory enumeration tanpa batas |
| **Login Attempts** | Mencegah brute-force | Brute-force tidak terdeteksi |
| **Endpoint Rate Limit** | Granular API protection | Semua endpoint sama perlakuan |
| **Behavioral** | Deteksi sophisticated bot | Bot behave-normal lolos |
| **JS Challenge** | Block headless browser | Headless browser attack possible |
| **Proxy / VPN** | Block proxied attacks | Attacker pakai VPN tanpa batas |
| **Distributed** | Block coordinated botnet | Distributed attack possible |
| **Slow & Low** | Block slow-bot attack | Slow attack tidak terdeteksi |
| **Session Anomaly** | Block session attacks | Stolen session attack possible |
| **Recidivist** | Auto permanent block repeat offender | Repeat attacker retry setiap expiry |
| **Whitelist** | Protect internal IPs | Internal IPs bisa terflag |
| **Blacklist** | Block known bad actors | Manual block tidak tersedia |
| **Email** | Real-time alert | Alert tidak dikirim |
| **Webhook** | Alert ke Slack/Discord/tools | Alert tidak dikirim |
| **Telemetry** | Centralized logging | Bot events di local log saja |

---

## Prioritas Detector Check Order

Bot Guardian memeriksa detector dalam urutan berikut:

```
Request masuk
  │
  ├─ 1. Whitelist check       → Bypass jika match
  ├─ 2. Blacklist check      → Immediate 403 jika match
  ├─ 3. Recidivist check     → Permanent block jika sudah permanen
  ├─ 4. Block cache check    → 403 jika IP sedang terblokir
  ├─ 5. Detector check #1    │ Semua detector jalan paralel
  ├─ 6. Detector check #2    │ Tidak ada early exit sampai semua selesai
  ├─ ...                     │
  ├─ 7. Score accumulation   │
  │   (jika score >= threshold → trigger block)
  └─ 8. Notification        (jika enabled)
```

Urutan whitelist/blacklist fixed — tidak bisa dikonfigurasi. Whitelist selalu di-check terlebih dahulu (bypass), baru blacklist (immediate block).
