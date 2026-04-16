<?php

namespace Febryntara\LaravelBotGuardian\Detectors;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

/**
 * Detector 404 spam — mendeteksi IP yang sering hit endpoint tidak ada.
 *
 * Bot scanner biasanya crawl banyak path yang tidak exist untuk mencari
 * vulnerability. Manusia normal jarang dapat 404 berkali-kali.
 */
class NotFoundDetector implements DetectorInterface
{
    public function detect(Request $request): int
    {
        if (! $this->isEnabled()) {
            return 0;
        }

        // Only activate for 404 responses — dipanggil after response
        // Middleware lain sudah set status code
        if ($request->route() === null) {
            $ip = $request->ip();
            $key = "botguardian:404:{$ip}";

            $config = config('botguardian.not_found_spam');
            $maxHits = $config['max_hits'] ?? 10;
            $timeWindow = $config['time_window'] ?? 60;
            $score = $config['score'] ?? 30;

            // FIX: Use atomic increment
            $count = Cache::increment($key);
            if ($count === 1) {
                Cache::put($key, 1, $timeWindow);
                $count = 1;
            } else {
                $count = Cache::get($key, $count);
            }

            if ($count > $maxHits) {
                return $score;
            }
        }

        return 0;
    }

    public function isEnabled(): bool
    {
        return config('botguardian.not_found_spam.enabled', true);
    }

    public function getName(): string
    {
        return 'not_found_spam';
    }
}
