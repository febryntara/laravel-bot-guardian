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
        'warning_threshold' => 0.8,
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
        'exclude_routes' => [],
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

    // === JS CHALLENGE ===
    'js_challenge' => [
        'enabled' => false,
        'secret' => 'botguardian-challenge-secret',
        'token_validity' => 300,
        'missing_token_score' => 35,
        'invalid_token_score' => 50,
        'skip_prefixes' => [
            'api/',
            '_debugbar/',
            'telescope/',
            'horizon/',
            'socket.io/',
            'ws/',
            'graphql',
        ],
        'challenge_api_routes' => [],
    ],

    // === PROXY / VPN ===
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

    // === DISTRIBUTED ATTACK ===
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
        'sensitive_patterns' => [
            'login', 'auth', 'password', 'reset', 'admin',
            'api/auth', 'api/login', 'api/reset',
        ],
        'max_score' => 60,
    ],

    // === SLOW & LOW ATTACK ===
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

    // === SESSION ANOMALY ===
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

    // === LOGIN ATTEMPTS ===
    'login_attempts' => [
        'enabled' => false,
        'max_attempts' => 5,
        'time_window' => 300,
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
        'endpoints' => [],
    ],

    // === BEHAVIORAL PATTERNS ===
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

    // === RECIDIVIST TRACKING ===
    'recidivist' => [
        'enabled' => true,
        'max_blocks_before_permanent' => 3,
        'count_window' => 86400,
    ],

    // === WHITELIST / BLACKLIST ===
    'whitelist' => [
        'enabled' => false,
        'ips' => [],
    ],
    'blacklist' => [
        'enabled' => false,
        'ips' => [],
    ],

    // === BLOCKING SETTINGS ===
    'threshold' => 100,
    'score_decay_window' => 300,
    'block_duration' => 3600,
    'block_view' => 'botguardian::blocked',

    // === LOGGING ===
    'log_enabled' => true,

    // === NOTIFICATIONS ===
    'notifications' => [
        // --- Email ---
        'email' => [
            'enabled' => false,
            'to' => ['admin@example.com'],
            'subject_prefix' => '[BotGuardian]',
        ],
        // --- Webhook ---
        'webhook' => [
            'enabled' => false,
            'url' => null,
            'secret' => null,
            'timeout' => 10,
            'retry' => 3,
            'include_context' => true,
        ],
    ],

    // === TELEMETRY LOG INTEGRATION ===
    // Requires febryntara/laravel-telemetry-logger package.
    // If installed + enabled, bot detection events are forwarded there automatically.
    'telemetry' => [
        'enabled' => false,
    ],
];
