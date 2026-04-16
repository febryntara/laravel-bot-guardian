<?php

namespace Febryntara\LaravelBotGuardian\Detectors;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

/**
 * JavaScript Challenge — mendeteksi headless browser & bot tanpa JS engine.
 *
 * HOW IT WORKS:
 * 1. Response interceptor injects inline JS that sets a verification cookie.
 *    - The JS runs AFTER the page loads, simulating real browser behavior.
 * 2. Subsequent requests checked for the verification token.
 * 3. Headless browsers (Puppeteer/Playwright without JS exec) miss this.
 *
 * CAVEATS:
 * - Bots WITH JS engine (Selenium, Playwright with JS enabled) CAN pass.
 * - For those, combine with BehavioralPatternDetector (timing, Sec-Fetch headers).
 * - API-only apps get no protection (no HTML response to inject JS into).
 *   Enable `challenge_api_routes` only if your API serves HTML content.
 *
 * CONFIG: botguardian.js_challenge
 */
class JsChallengeDetector implements DetectorInterface
{
    protected const COOKIE_NAME = 'bg_chk';

    public function detect(Request $request): int
    {
        if (! $this->isEnabled()) {
            return 0;
        }

        $config = config('botguardian.js_challenge');

        // API routes without HTML content — skip challenge
        if (! $this->shouldChallenge($request, $config)) {
            return 0;
        }

        $ip = $request->ip();
        $token = $request->cookie(self::COOKIE_NAME);

        if (empty($token)) {
            return $config['missing_token_score'] ?? 30;
        }

        // Verify token integrity (signed with IP + timestamp)
        $expected = $this->generateToken($ip);
        if (! hash_equals($expected, $token)) {
            return $config['invalid_token_score'] ?? 40;
        }

        return 0;
    }

    /**
     * Should this request be challenged?
     * - First-time visitors: never blocked (no cookie yet, this IS the challenge request)
     * - Returning visitors: must have valid bg_chk token
     */
    protected function shouldChallenge(Request $request, array $config): bool
    {
        // Normalize path without leading slash to match config prefixes (no leading /)
        $path = ltrim($request->path(), '/');

        // Never challenge these paths
        $skipPrefixes = $config['skip_prefixes'] ?? [
            'api/', '_debugbar/', 'telescope/', 'horizon/',
        ];
        foreach ($skipPrefixes as $prefix) {
            if (str_starts_with($path, $prefix)) {
                return false;
            }
        }

        // Always challenge HTML routes (has potential form/action)
        if ($this->isHtmlRoute($request)) {
            return true;
        }

        // Optionally challenge API routes that serve HTML content
        $apiRoutes = $config['challenge_api_routes'] ?? [];
        if (! empty($apiRoutes)) {
            foreach ($apiRoutes as $pattern) {
                if (fnmatch($pattern, $path)) {
                    return true;
                }
            }
        }

        return false;
    }

    protected function isHtmlRoute(Request $request): bool
    {
        $accept = $request->header('Accept', '');
        // Normalize path without leading slash to match config prefixes (no leading /)
        $path = ltrim($request->path(), '/');

        // Explicit HTML
        if (str_contains($accept, 'text/html')) {
            return true;
        }

        // Path-based heuristics for HTML routes (path has NO leading /)
        $htmlPaths = ['home', 'dashboard', 'admin',
            'login', 'register', 'checkout', 'cart', 'search',
            'profile', 'account', 'contact', 'about'];
        foreach ($htmlPaths as $p) {
            if ($path === $p || str_starts_with($path, $p . '/')) {
                return true;
            }
        }

        // No Accept header AND no extension → likely browser navigation
        if (empty($accept) && ! str_contains($path, '.')) {
            return true;
        }

        return false;
    }

    /**
     * Generate a signed token for the given IP.
     * Token = HMAC-SHA256(ip + timestamp bucket, secret key)
     * Timestamp bucket = floor(time() / bucket_size) so token is valid for bucket_size seconds.
     */
    public function generateToken(string $ip): string
    {
        $config = config('botguardian.js_challenge');
        $secret = $config['secret'] ?? 'botguardian-challenge-secret';
        $bucketSize = $config['token_validity'] ?? 300; // 5 min buckets

        $bucket = floor(time() / $bucketSize);
        $payload = "{$ip}|{$bucket}";

        return hash_hmac('sha256', $payload, $secret);
    }

    /**
     * Cookie name constant for use by middleware (injectChallengeCookie).
     */
    public static function cookieName(): string
    {
        return self::COOKIE_NAME;
    }

    public function isEnabled(): bool
    {
        return config('botguardian.js_challenge.enabled', false);
    }

    public function getName(): string
    {
        return 'js_challenge';
    }
}
