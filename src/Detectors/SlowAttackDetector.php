<?php

namespace Febryntara\LaravelBotGuardian\Detectors;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

/**
 * Slow & Low Attack Detection — mendeteksi bot yang sengaja lambat.
 *
 * ATTACK MODEL:
 * 1 req / 2 menit selama 24 jam = 720 req total.
 * Velocity detector (30 req/min) tidak akan pernah kena.
 * Tapi 720 req dalam 24h ke endpoint sensitif = credential stuffing.
 *
 * DETECTION STRATEGY:
 * 1. Long-window velocity: track total requests over 24h period.
 *    Threshold: human正常使用不超过 500-1000 req/hari.
 * 2. Interval entropy: if requests arrive with unnaturally even spacing,
 *    it's a script (even if slow). Uses standard deviation.
 * 3. Endpoint diversity: real users browse many pages; bots stick to few targets.
 *
 * CONFIG: botguardian.slow_attack
 */
class SlowAttackDetector implements DetectorInterface
{
    public function detect(Request $request): int
    {
        if (! $this->isEnabled()) {
            return 0;
        }

        $config = config('botguardian.slow_attack');
        $score = 0;

        $ip = $request->ip();
        $path = '/' . ltrim($request->path(), '/');

        // === Check 1: Long-window request count (24h total) ===
        $score += $this->checkLongWindowVelocity($ip, $config);

        // === Check 2: Regular interval (slow bot still has even spacing) ===
        $score += $this->checkSlowInterval($ip, $config);

        // === Check 3: Endpoint cardinality (few endpoints = script) ===
        $score += $this->checkEndpointDiversity($ip, $path, $config);

        return min($score, $config['max_score'] ?? 60);
    }

    protected function checkLongWindowVelocity(string $ip, array $config): int
    {
        $window = $config['long_window'] ?? 86400; // 24h
        $threshold = $config['daily_request_limit'] ?? 2000;
        $score = $config['long_window_score'] ?? 20;

        $key = "botguardian:slow:long:{$ip}";
        $count = Cache::increment($key);
        if ($count === 1) {
            Cache::put($key, 1, $window);
        } else {
            $count = Cache::get($key, $count);
        }

        // Only score when significantly over limit (avoid false positives)
        if ($count > $threshold) {
            $excess = $count - $threshold;
            $penalty = (int) min($excess / 100, $score);
            return $penalty > 0 ? $penalty : $score;
        }

        return 0;
    }

    protected function checkSlowInterval(string $ip, array $config, array $intervals = null): int
    {
        $window = $config['interval_window'] ?? 600;
        $key = "botguardian:slow:intervals:{$ip}";

        if ($intervals === null) {
            $intervals = Cache::get($key, []);
        }
        $now = microtime(true);
        $intervals[] = $now;

        if (count($intervals) > 30) {
            $intervals = array_slice($intervals, -30);
        }
        Cache::put($key, $intervals, $window);

        if (count($intervals) < 5) {
            return 0;
        }

        // Sort ascending so diff calculation is always chronological.
        // (Entries from test setup may be in any order.)
        sort($intervals);

        $diffs = [];
        for ($i = 1; $i < count($intervals); $i++) {
            $diffs[] = $intervals[$i] - $intervals[$i - 1];
        }

        $mean = array_sum($diffs) / count($diffs);
        $variance = 0;
        foreach ($diffs as $d) {
            $variance += pow($d - $mean, 2);
        }
        $stddev = sqrt($variance / count($diffs));

        if ($mean > 10) {
            $relativeStddev = $stddev / $mean;
            if ($relativeStddev < ($config['interval_coef_threshold'] ?? 0.1)) {
                return $config['regular_interval_score'] ?? 25;
            }
        }

        return 0;
    }

    protected function checkEndpointDiversity(string $ip, string $path, array $config): int
    {
        $window = $config['diversity_window'] ?? 3600; // 1h
        $minRequests = $config['min_requests_for_diversity'] ?? 20;
        $minUniqueEndpoints = $config['min_unique_endpoints'] ?? 5;
        $score = $config['low_diversity_score'] ?? 30;

        $countKey = "botguardian:slow:count:{$ip}";
        $endpointsKey = "botguardian:slow:endpoints:{$ip}";

        $count = Cache::increment($countKey);
        if ($count === 1) {
            Cache::put($countKey, 1, $window);
        } else {
            $count = Cache::get($countKey, $count);
        }

        if ($count < $minRequests) {
            return 0;
        }

        $endpoints = Cache::get($endpointsKey, []);
        $normalizedPath = $this->normalizeEndpoint($path);

        if (! in_array($normalizedPath, $endpoints)) {
            $endpoints[] = $normalizedPath;
            Cache::put($endpointsKey, $endpoints, $window);
        }

        if (count($endpoints) < $minUniqueEndpoints) {
            return $score;
        }

        return 0;
    }

    /**
     * Normalize endpoint to reduce false diversity from URL params.
     * /api/users/123 → /api/users/:id
     * /products/abc → /products/:id
     */
    protected function normalizeEndpoint(string $path): string
    {
        // Remove query string
        $path = explode('?', $path)[0];

        // Replace numeric segments with :id
        $normalized = preg_replace('/\/\d+/', '/:id', $path);

        // Replace alphanumeric UUID-style segments
        $normalized = preg_replace('/\/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/i', '/:id', $normalized);

        return $normalized;
    }

    public function isEnabled(): bool
    {
        return config('botguardian.slow_attack.enabled', false);
    }

    public function getName(): string
    {
        return 'slow_attack';
    }
}
