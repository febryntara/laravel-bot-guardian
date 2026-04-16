<?php

namespace Febryntara\LaravelBotGuardian\Detectors;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class VelocityDetector implements DetectorInterface
{
    public function detect(Request $request): int
    {
        if (! $this->isEnabled()) {
            return 0;
        }

        $config = config('botguardian.velocity');
        $ip = $request->ip();
        $key = "botguardian:velocity:{$ip}";
        $maxRequests = $config['max_requests'] ?? 30;
        $timeWindow = $config['time_window'] ?? 60;
        $score = $config['score'] ?? 20;

        // FIX: Use atomic increment to avoid race condition.
        // Cache::increment() returns the NEW value after increment.
        // We check AFTER increment — if > max, the request triggered the excess.
        $count = Cache::increment($key);

        // Set expiry only on first increment
        if ($count === 1) {
            Cache::put($key, 1, $timeWindow);
            $count = 1;
        } else {
            $count = Cache::get($key, $count);
        }

        if ($count > $maxRequests) {
            return $score;
        }

        return 0;
    }

    public function isEnabled(): bool
    {
        return config('botguardian.velocity.enabled', true);
    }

    public function getName(): string
    {
        return 'velocity';
    }
}
