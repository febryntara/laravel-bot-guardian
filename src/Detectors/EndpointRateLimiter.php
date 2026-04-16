<?php

namespace Febryntara\LaravelBotGuardian\Detectors;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

/**
 * Per-endpoint rate limiting.
 * Tidak semua endpoint sama — login form bisa di-browse unlimited,
 * tapi login POST harus dibatasi ketat. API submit harus dibatasi ketat.
 *
 * Konsep: tiap endpoint punya limits sendiri berdasarkan kategori:
 *   - public     : browse-like, higher limit
 *   - sensitive  : auth, submit, API write — lower limit, higher score
 *   - critical   : password reset, payment — very low limit, very high score
 */
class EndpointRateLimiter implements DetectorInterface
{
    protected array $defaultLimits = [
        'public' => ['max' => 60, 'window' => 60, 'score' => 10],
        'sensitive' => ['max' => 10, 'window' => 60, 'score' => 30],
        'critical' => ['max' => 3, 'window' => 300, 'score' => 60],
    ];

    public function detect(Request $request): int
    {
        if (! $this->isEnabled()) {
            return 0;
        }

        $path = '/' . ltrim($request->path(), '/');
        $method = strtoupper($request->method());
        $ip = $request->ip();
        $config = config('botguardian.endpoint_rate_limits');

        // Determine endpoint category and limits
        $limits = $this->resolveLimits($path, $method, $config);
        $key = "botguardian:epr:{$ip}:{$path}";

        // Atomic increment
        $current = Cache::increment($key);
        if ($current === 1) {
            Cache::put($key, 1, $limits['window']);
        } else {
            $current = Cache::get($key, 1);
        }

        if ($current > $limits['max']) {
            return $limits['score'];
        }

        return 0;
    }

    protected function resolveLimits(string $path, string $method, array $config): array
    {
        // 1. Check explicit endpoint overrides
        $endpoints = $config['endpoints'] ?? [];
        foreach ($endpoints as $pattern => $setting) {
            if ($this->pathMatches($path, $pattern)) {
                return $setting;
            }
        }

        // 2. Check method-based defaults
        $sensitiveMethods = ['POST', 'PUT', 'PATCH', 'DELETE'];
        $criticalMethods = ['POST', 'PUT', 'PATCH'];

        if (in_array($method, $criticalMethods) && $this->isCriticalPath($path, $config)) {
            return $config['critical'] ?? $this->defaultLimits['critical'];
        }

        if (in_array($method, $sensitiveMethods)) {
            return $config['sensitive'] ?? $this->defaultLimits['sensitive'];
        }

        return $config['public'] ?? $this->defaultLimits['public'];
    }

    protected function isCriticalPath(string $path, array $config): bool
    {
        $criticalPatterns = $config['critical_patterns'] ?? [
            'password', 'payment', 'checkout', 'transfer',
            'api/*/auth', 'api/*/login', 'reset-password',
        ];

        foreach ($criticalPatterns as $pattern) {
            if ($this->pathMatches($path, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Simple glob-like pattern matching:
     *   /login          → exact match
     *   /api/*          → any single segment under /api/
     *   /api/**         → any path under /api/
     */
    protected function pathMatches(string $path, string $pattern): bool
    {
        $pattern = '/' . ltrim($pattern, '/');

        // Exact match
        if ($path === $pattern) {
            return true;
        }

        // Glob patterns
        if (str_contains($pattern, '**')) {
            $prefix = str_replace('**', '', $pattern);
            $prefix = rtrim($prefix, '/');
            if (str_starts_with($path, $prefix)) {
                return true;
            }
        }

        if (str_contains($pattern, '*')) {
            $prefix = str_replace('*', '', $pattern);
            $prefix = rtrim($prefix, '/');
            $remaining = substr($path, strlen($prefix));

            // Verify it's exactly one segment
            if (str_starts_with($remaining, '/') && substr_count($remaining, '/') === 1) {
                return true;
            }
        }

        return false;
    }

    public function isEnabled(): bool
    {
        return config('botguardian.endpoint_rate_limits.enabled', false);
    }

    public function getName(): string
    {
        return 'endpoint_rate_limit';
    }
}
