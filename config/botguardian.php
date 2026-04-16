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
