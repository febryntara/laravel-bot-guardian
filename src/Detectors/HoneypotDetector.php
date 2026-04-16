<?php

namespace Febryntara\LaravelBotGuardian\Detectors;

use Illuminate\Http\Request;

class HoneypotDetector implements DetectorInterface
{
    public function detect(Request $request): int
    {
        if (! $this->isEnabled()) {
            return 0;
        }

        $config = config('botguardian.honeypot');
        $honeypotRoutes = $config['routes'] ?? [];
        $excludeRoutes = $config['exclude_routes'] ?? []; // NEW: per-route exclusions
        $score = $config['score'] ?? 50;

        $path = '/' . ltrim($request->path(), '/');

        // Check exclusions first — excluded routes always return 0
        foreach ($excludeRoutes as $route) {
            $excludePath = '/' . ltrim($route, '/');
            if ($path === $excludePath || str_starts_with($path, rtrim($excludePath, '/') . '/')) {
                return 0;
            }
        }

        foreach ($honeypotRoutes as $route) {
            $honeypotPath = '/' . ltrim($route, '/');
            if ($path === $honeypotPath || str_starts_with($path, rtrim($honeypotPath, '/') . '/')) {
                return $score;
            }
        }

        return 0;
    }

    public function isEnabled(): bool
    {
        return config('botguardian.honeypot.enabled', true);
    }

    public function getName(): string
    {
        return 'honeypot';
    }
}
