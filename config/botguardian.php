<?php
return [
    // Master toggle
    'enabled' => true,

    // === VELOCITY ===
    'velocity' => [
        'enabled' => true,
        'max_requests' => 30,
        'time_window' => 60,
        'score' => 20,
        'warning_threshold' => 0.8, // Log warning at 80% of limit (req 24 of 30)
    ],

    // === 404 SPAM ===
    'not_found_spam' => [
        'enabled' => true,
        'max_hits' => 10,
        'time_window' => 60,
        'score' => 30,
    ],

    // === HONEYPOT ===
    'honeypot' => [
        'enabled' => true,
        'routes' => [
            '/wp-admin',
            '/wp-login.php',
            '/.env',
            '/.env.bak',
            '/api/.env',
            '/phpMyAdmin',
            '/pma',
            '/admin.php',
            '/login.php',
            '/shell.php',
        ],
        'exclude_routes' => [
            // Exclude specific paths from honeypot detection
            // e.g., '/admin.php' => your real admin URL
        ],
        'score' => 50,
    ],

    // === HEADERS ===
    'headers' => [
        'enabled' => true,
        'block_empty_user_agent' => true,
        'empty_user_agent_score' => 25,
        'block_known_bots' => true,
        'known_bot_patterns' => [
            'python-requests',
            'python-httpx',
            'Go-http-client',
            'curl/',
            'Wget/',
            'Java/',
            'PHP/',
            'node-fetch',
            'axios/',
            'Scrapy',
        ],
        'known_bot_score' => 15,
        'missing_accept_language_score' => 10,
    ],

    // === JS CHALLENGE (headless browser / UA spoofing) ===
    // Requires legitimate visitors to execute JavaScript (sets a verification cookie).
    // NOT effective for API-only apps or when JS challenge is disabled.
    // Combine with BehavioralPatternDetector for defense-in-depth.
    'js_challenge' => [
        'enabled' => false,
        'secret' => 'botguardian-challenge-secret', // CHANGE this in production!
        'token_validity' => 300, // seconds, token valid for this bucket
        'missing_token_score' => 35,
        'invalid_token_score' => 50,
        'skip_prefixes' => [
            'api/', '_debugbar/', 'telescope/', 'horizon/',
            'socket.io/', 'ws/', 'graphql',
        ],
        'challenge_api_routes' => [], // Routes that serve HTML content via API
    ],

    // === PROXY / VPN / TOR DETECTION (header chain analysis) ===
    // Probabilistic — false positives possible for users behind corporate CDN/proxy.
    // Tune thresholds for your infrastructure (Cloudflare = expect Via/XFF headers).
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

    // === DISTRIBUTED ATTACK (multi-IP coordinated botnet) ===
    // Detects: 1000 IPs × 1 req each → all under velocity threshold but targeted.
    // Strategy: fingerprint clustering (same UA = same bot) + endpoint concentration.
    'distributed' => [
        'enabled' => false,
        'window' => 120,
        'ips_per_fingerprint' => 10,     // Flag if >10 IPs share same UA fingerprint
        'score_per_ip' => 2,
        'max_fingerprint_score' => 30,
        'endpoint_window' => 300,
        'ips_per_endpoint' => 20,         // Flag if >20 IPs hit same sensitive endpoint
        'score_per_ip' => 1,
        'max_endpoint_score' => 30,
        'sensitive_patterns' => [
            'login', 'auth', 'password', 'reset', 'admin',
            'api/auth', 'api/login', 'api/reset',
        ],
        'max_score' => 60,
    ],

    // === SLOW & LOW ATTACK (bypass velocity by being slow) ===
    // Detects: 1 req/2min × 24h = 720 req (no velocity trigger, but abnormal total).
    // Strategy: long-window total + interval entropy + endpoint diversity.
    'slow_attack' => [
        'enabled' => false,
        'long_window' => 86400, // 24h total request tracking
        'daily_request_limit' => 2000,
        'long_window_score' => 20,
        'interval_window' => 600,
        'interval_coef_threshold' => 0.1,  // stddev/mean < 10% = suspicious
        'regular_interval_score' => 25,
        'diversity_window' => 3600,
        'min_requests_for_diversity' => 20,
        'min_unique_endpoints' => 5,
        'low_diversity_score' => 30,
        'max_score' => 60,
    ],

    // === SESSION ANOMALY (fixation / hijacking detection) ===
    // Tracks: session ID changes (fixation), multi-IP sessions (hijacking),
    // session burst rate (automated attacks via stolen session).
    // Requires Laravel session middleware running before BotGuardian.
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

    // === LOGIN ATTEMPTS (brute-force) ===
    'login_attempts' => [
        'enabled' => false, // Enable manually for auth-heavy apps
        'max_attempts' => 5,
        'time_window' => 300, // 5 minutes
        'score' => 40,
        'routes' => [
            'login', 'auth/login', 'admin/login',
            'api/login', 'api/auth/login', 'authenticate',
        ],
    ],

    // === PER-ENDPOINT RATE LIMITING ===
    'endpoint_rate_limits' => [
        'enabled' => false,
        'public' => ['max' => 60, 'window' => 60, 'score' => 10],
        'sensitive' => ['max' => 10, 'window' => 60, 'score' => 30],
        'critical' => ['max' => 3, 'window' => 300, 'score' => 60],
        'critical_patterns' => [
            'password', 'payment', 'checkout', 'transfer',
            'api/*/auth', 'api/*/login', 'reset-password',
        ],
        'endpoints' => [
            // '/api/submit-form' => ['max' => 5, 'window' => 60, 'score' => 50],
            // Override specific endpoints here
        ],
    ],

    // === BEHAVIORAL PATTERNS ===
    'behavioral' => [
        'enabled' => false,
        'window' => 120,
        'max_score' => 50,
        // No-asset pattern: hits API only, no CSS/JS/images
        'check_no_asset' => true,
        'no_asset_min_requests' => 10,
        'no_asset_ratio_threshold' => 0.1, // min 10% must be asset requests
        'no_asset_score' => 25,
        // Regular interval: requests arrive suspiciously evenly spaced
        'check_regular_interval' => true,
        'interval_stddev_threshold' => 0.05, // seconds
        'regular_interval_score' => 30,
        // Header fingerprint mismatch
        'check_header_fingerprint' => true,
        'missing_sec_fetch_score' => 15,
        'missing_accept_score' => 5,
        'inconsistent_accept_score' => 10,
        'fingerprint_mismatch_score' => 15,
        // Deep-link without referer
        'check_deep_links' => true,
        'min_deep_links' => 5,
        'deep_link_score' => 20,
    ],

    // === RECIDIVIST TRACKING (permanent block for repeat offenders) ===
    'recidivist' => [
        'enabled' => true,
        'max_blocks_before_permanent' => 3,
        'count_window' => 86400, // 24 hours, count resets after this
    ],

    // === WHITELIST / BLACKLIST ===
    'whitelist' => [
        'enabled' => false,
        'ips' => [
            // '127.0.0.1',
            // '192.168.0.0/24',
            // '10.*.1.1',
        ],
    ],
    'blacklist' => [
        'enabled' => false,
        'ips' => [
            // Known malicious IPs here
        ],
    ],

    // === BLOCKING SETTINGS ===
    'threshold' => 100,
    'score_decay_window' => 300,
    'block_duration' => 3600, // 1 hour
    'block_view' => 'botguardian::blocked',

    // === LOGGING ===
    'log_enabled' => true,
    'log_to_database' => false,
    'notify_on_block' => false,
];
