<?php

namespace Febryntara\LaravelBotGuardian\Detectors;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

/**
 * Behavioral pattern detection — mendeteksi bot berdasarkan cara browsing.
 *
 * Checks:
 * 1. No-asset pattern  : hanya hit API endpoints, tidak pernah load CSS/JS/images
 * 2. Regular interval  : request dengan timing yang terlalu konsisten (robotic)
 * 3. Rapid deep links  : langsung ke halaman dalam tanpa browse flow
 * 4. Suspicious fingerprint: header yang inconsistent
 */
class BehavioralPatternDetector implements DetectorInterface
{
    /**
     * Asset file extensions — request ini normal dan menunjukkan browser nyata.
     */
    protected array $assetExtensions = [
        '.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico',
        '.woff', '.woff2', '.ttf', '.eot', '.map', '.webp', '.mp4', '.webm',
    ];

    public function detect(Request $request): int
    {
        if (! $this->isEnabled()) {
            return 0;
        }

        $ip = $request->ip();
        $path = '/' . ltrim($request->path(), '/');
        $config = config('botguardian.behavioral');
        $score = 0;

        // === Check 1: No-asset pattern ===
        if (! empty($config['check_no_asset'])) {
            $score += $this->checkNoAssetPattern($ip, $path, $config);
        }

        // === Check 2: Regular interval (robotic timing) ===
        if (! empty($config['check_regular_interval'])) {
            $score += $this->checkRegularInterval($ip, $config);
        }

        // === Check 3: Suspicious header fingerprint ===
        if (! empty($config['check_header_fingerprint'])) {
            $score += $this->checkHeaderFingerprint($request, $config);
        }

        // === Check 4: Deep-link pattern ===
        if (! empty($config['check_deep_links'])) {
            $score += $this->checkDeepLinkPattern($request, $ip, $config);
        }

        return min($score, $config['max_score'] ?? 50);
    }

    protected function checkNoAssetPattern(string $ip, string $path, array $config): int
    {
        $minRequests = $config['no_asset_min_requests'] ?? 10;
        $window = $config['window'] ?? 120;
        $assetThreshold = $config['no_asset_ratio_threshold'] ?? 0.1; // 10% assets minimum

        // Skip asset requests
        if ($this->isAssetPath($path)) {
            $key = "botguardian:behavior:{$ip}:assets";
            $current = Cache::increment($key);
            if ($current === 1) {
                Cache::put($key, 1, $window);
            }
            return 0;
        }

        $totalKey = "botguardian:behavior:{$ip}:total";
        $assetKey = "botguardian:behavior:{$ip}:assets";

        $total = Cache::increment($totalKey);
        if ($total === 1) {
            Cache::put($totalKey, 1, $window);
        }

        $total = Cache::get($totalKey, 1);
        $assets = Cache::get($assetKey, 0);

        // Need minimum requests before evaluating
        if ($total < $minRequests) {
            return 0;
        }

        $assetRatio = $assets / $total;
        if ($assetRatio < $assetThreshold && $total > $minRequests) {
            return $config['no_asset_score'] ?? 25;
        }

        return 0;
    }

    protected function isAssetPath(string $path): bool
    {
        foreach ($this->assetExtensions as $ext) {
            if (str_ends_with(strtolower($path), $ext)) {
                return true;
            }
        }
        return false;
    }

    protected function checkRegularInterval(string $ip, array $config): int
    {
        $window = $config['window'] ?? 120;
        $key = "botguardian:behavior:{$ip}:intervals";

        $intervals = Cache::get($key, []);

        // Record current timestamp
        $now = microtime(true);
        $intervals[] = $now;

        // Keep last N intervals
        $maxStored = 20;
        if (count($intervals) > $maxStored) {
            $intervals = array_slice($intervals, -$maxStored);
        }

        Cache::put($key, $intervals, $window);

        // Need at least 5 intervals to check
        if (count($intervals) < 5) {
            return 0;
        }

        // Calculate interval variance
        $diffs = [];
        for ($i = 1; $i < count($intervals); $i++) {
            $diffs[] = $intervals[$i] - $intervals[$i - 1];
        }

        if (empty($diffs)) {
            return 0;
        }

        $mean = array_sum($diffs) / count($diffs);
        $variance = 0;
        foreach ($diffs as $d) {
            $variance += pow($d - $mean, 2);
        }
        $stddev = sqrt($variance / count($diffs));

        // If stddev < threshold (e.g., 0.05s), timing is suspiciously regular
        // Humans have high variance; bots have low variance
        $threshold = $config['interval_stddev_threshold'] ?? 0.05;
        if ($stddev < $threshold && $mean > 0.1) {
            return $config['regular_interval_score'] ?? 30;
        }

        return 0;
    }

    protected function checkHeaderFingerprint(Request $request, array $config): int
    {
        $score = 0;

        $ua = $request->userAgent() ?? '';

        // Check 1: Chrome UA but missing Sec-Fetch-* headers (headless / curl)
        if (stripos($ua, 'Chrome') !== false || stripos($ua, 'Safari') !== false) {
            $hasSecFetch = $request->hasHeader('Sec-Fetch-Site')
                || $request->hasHeader('Sec-Fetch-Mode')
                || $request->hasHeader('Sec-Fetch-Dest');

            $hasAccept = $request->hasHeader('Accept')
                && ! empty($request->header('Accept'));

            if (! $hasSecFetch && ! empty($ua)) {
                $score += $config['missing_sec_fetch_score'] ?? 15;
            }

            if (! $hasAccept) {
                $score += $config['missing_accept_score'] ?? 5;
            }
        }

        // Check 2: Inconsistent Accept header
        $accept = $request->header('Accept', '');
        if (! empty($accept) && str_contains($accept, 'text/html')) {
            // Browser asking for HTML — check if UA matches browser
            if (empty($ua) || stripos($ua, 'Mozilla') === false) {
                $score += $config['inconsistent_accept_score'] ?? 10;
            }
        }

        // Check 3: Suspicious combination (mobile UA + desktop screen hints via header)
        if (preg_match('/Mobile|Android|iPhone/', $ua)) {
            if ($request->hasHeader('Viewport-Width') && $request->header('Viewport-Width') > 768) {
                $score += $config['fingerprint_mismatch_score'] ?? 15;
            }
        }

        return $score;
    }

    protected function checkDeepLinkPattern(Request $request, string $ip, array $config): int
    {
        $window = $config['window'] ?? 300;
        $minDeepLinks = $config['min_deep_links'] ?? 5;

        $deepKey = "botguardian:behavior:{$ip}:deeplinks";

        $referer = $request->header('Referer') ?? $request->header('Referrer') ?? '';

        if (empty($referer)) {
            // No referer — potential deep link
            $current = Cache::increment($deepKey);
            if ($current === 1) {
                Cache::put($deepKey, 1, $window);
            }

            $total = Cache::get($deepKey, 1);
            if ($total >= $minDeepLinks) {
                return $config['deep_link_score'] ?? 20;
            }
        } else {
            // Has referer — reset deep link counter
            Cache::put($deepKey, 0, $window);
        }

        return 0;
    }

    public function isEnabled(): bool
    {
        return config('botguardian.behavioral.enabled', false);
    }

    public function getName(): string
    {
        return 'behavioral_pattern';
    }
}
