<?php

namespace Febryntara\LaravelBotGuardian\Detectors;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

/**
 * Mendeteksi brute force di login / auth endpoints.
 * Track jumlah login attempt per IP per username, atau per IP keseluruhan.
 * Jika melebihi threshold → trigger block.
 */
class LoginAttemptDetector implements DetectorInterface
{
    /**
     * Auth endpoints yang ingin dimonitor.
     * Bisa override via config.
     */
    protected array $authRoutes = [
        'login', 'auth/login', 'admin/login',
        'api/login', 'api/auth/login', 'authenticate',
    ];

    public function detect(Request $request): int
    {
        if (! $this->isEnabled()) {
            return 0;
        }

        $path = '/' . ltrim($request->path(), '/');
        $config = config('botguardian.login_attempts');

        if (! $this->isAuthRoute($path, $config)) {
            return 0;
        }

        // Hanya check untuk method POST (actual login attempt)
        if (! in_array(strtoupper($request->method()), ['POST', 'PUT', 'PATCH'])) {
            return 0;
        }

        $ip = $request->ip();
        $maxAttempts = $config['max_attempts'] ?? 5;
        $timeWindow = $config['time_window'] ?? 300; // 5 menit default
        $score = $config['score'] ?? 40;

        // Gunakan atomic increment untuk avoid race condition
        $key = "botguardian:login_attempts:{$ip}";
        $attempts = Cache::increment($key);

        // Set expiry hanya saat first attempt (increment returns 1 on first)
        if ($attempts === 1) {
            Cache::put($key, 1, $timeWindow);
            $attempts = 1;
        } else {
            $attempts = Cache::get($key, 1);
        }

        if ($attempts > $maxAttempts) {
            return $score;
        }

        return 0;
    }

    protected function isAuthRoute(string $path, array $config): bool
    {
        $routes = $config['routes'] ?? $this->authRoutes;

        foreach ($routes as $route) {
            $routePath = '/' . ltrim($route, '/');
            if ($path === $routePath || str_starts_with($path, rtrim($routePath, '/') . '/')) {
                return true;
            }
        }

        return false;
    }

    public function isEnabled(): bool
    {
        return config('botguardian.login_attempts.enabled', false);
    }

    public function getName(): string
    {
        return 'login_attempts';
    }
}
