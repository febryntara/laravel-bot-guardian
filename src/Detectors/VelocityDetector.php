<?php

namespace Febryntara\LaravelBotGuardian\Detectors;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

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
        $warningThreshold = $config['warning_threshold'] ?? 0.8; // 80% of max

        // Atomic increment
        $count = Cache::increment($key);
        if ($count === 1) {
            Cache::put($key, 1, $timeWindow);
            $count = 1;
        } else {
            $count = Cache::get($key, $count);
        }

        // NEW: warning mode — log when approaching limit, before scoring kicks in
        $warnAt = (int) ceil($maxRequests * $warningThreshold);
        if ($count === $warnAt) {
            Log::info('Bot Guardian: Velocity warning', [
                'ip' => $ip,
                'requests' => $count,
                'max' => $maxRequests,
                'window' => $timeWindow,
                'message' => "IP approaching rate limit ({$count}/{$maxRequests})",
            ]);
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
