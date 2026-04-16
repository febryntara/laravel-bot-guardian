<?php

namespace Febryntara\LaravelBotGuardian\Detectors;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

/**
 * NotFoundDetector — 404 spam detection.
 *
 * FIX #7: This detector is EXCLUDED from BotScoreCalculator's default list.
 * Primary 404 detection is handled in BotGuardianMiddleware::terminate()
 * via BotScoreCalculator::increment404(), which uses the ACTUAL HTTP 404 status code.
 *
 * This detect() method remains as a FALLBACK for cases where:
 * - terminate() is not called (non-Laravel context)
 * - standalone usage without the full middleware
 *
 * It uses the same cache key so the two systems share state.
 */
class NotFoundDetector implements DetectorInterface
{
    public function detect(Request $request): int
    {
        if (! $this->isEnabled()) {
            return 0;
        }

        // Same key as increment404() in BotScoreCalculator
        $ip = $request->ip();
        $key = "botguardian:404:{$ip}";

        $config = config('botguardian.not_found_spam');
        $maxHits = $config['max_hits'] ?? 10;
        $score = $config['score'] ?? 30;

        $count = Cache::increment($key);
        if ($count === 1) {
            // Set expiry only on first increment (1 second for fallback, short-lived)
            Cache::put($key, 1, 1);
            $count = 1;
        } else {
            $count = Cache::get($key, $count);
        }

        if ($count > $maxHits) {
            return $score;
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
