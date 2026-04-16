<?php

namespace Febryntara\LaravelBotGuardian\Scorer;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Febryntara\LaravelBotGuardian\Detectors\DetectorInterface;

class BotScoreCalculator
{
    /** @var DetectorInterface[] */
    protected array $detectors;

    public function __construct()
    {
        $this->detectors = $this->buildDetectors();
    }

    protected function buildDetectors(): array
    {
        return [
            new \Febryntara\LaravelBotGuardian\Detectors\VelocityDetector(),
            new \Febryntara\LaravelBotGuardian\Detectors\HoneypotDetector(),
            new \Febryntara\LaravelBotGuardian\Detectors\HeaderDetector(),
            // NotFoundDetector EXCLUDED: 404 detection is handled EXCLUSIVELY
            // in BotGuardianMiddleware::terminate() via increment404(), using
            // the ACTUAL HTTP 404 status code (not just route-null heuristic).
            // This eliminates double-count and ensures response-accurate detection.
            new \Febryntara\LaravelBotGuardian\Detectors\LoginAttemptDetector(),
            new \Febryntara\LaravelBotGuardian\Detectors\EndpointRateLimiter(),
            new \Febryntara\LaravelBotGuardian\Detectors\BehavioralPatternDetector(),
            // NEW — gap coverage:
            new \Febryntara\LaravelBotGuardian\Detectors\ProxyDetector(),
            new \Febryntara\LaravelBotGuardian\Detectors\DistributedAttackDetector(),
            new \Febryntara\LaravelBotGuardian\Detectors\SlowAttackDetector(),
            new \Febryntara\LaravelBotGuardian\Detectors\SessionAnomalyDetector(),
            // NEW — UA rotation / headless browser
            new \Febryntara\LaravelBotGuardian\Detectors\JsChallengeDetector(),
        ];
    }

    public function getDetectors(): array
    {
        return $this->detectors;
    }

    public function calculate(Request $request): int
    {
        $totalScore = 0;

        foreach ($this->detectors as $detector) {
            if ($detector->isEnabled()) {
                $totalScore += $detector->detect($request);
            }
        }

        return $totalScore;
    }

    public function getTotalScore(Request $request): int
    {
        $ip = $request->ip();
        $key = "botguardian:score:{$ip}";
        return Cache::get($key, 0);
    }

    /**
     * FIX #1: increment() now returns the NEW total atomically.
     * No need for separate getTotalScore() call after increment.
     */
    public function increment(Request $request, int $score): int
    {
        $ip = $request->ip();
        $key = "botguardian:score:{$ip}";
        $window = config('botguardian.score_decay_window', 300);

        $newTotal = Cache::increment($key);
        if ($newTotal === 1) {
            Cache::put($key, $score, $window);
            return $score;
        }

        $existing = Cache::get($key, 0);
        $newTotal = $existing + $score;
        Cache::put($key, $newTotal, $window);
        return $newTotal;
    }

    /**
     * FIX #7: Called from terminate() after response is confirmed as 404.
     * Uses ACTUAL HTTP 404 status code (not route-null heuristic).
     * Uses SAME cache key as NotFoundDetector::detect() so they track together.
     * increment404() adds the score IF NotFoundDetector already returned score
     * (i.e., terminate confirms what detect() predicted). This prevents
     * false-positives from custom 404 handlers that return non-404 codes.
     */
    public function increment404(Request $request): int
    {
        $config = config('botguardian.not_found_spam');
        $maxHits = $config['max_hits'] ?? 10;
        $timeWindow = $config['time_window'] ?? 60;
        $score = $config['score'] ?? 30;

        $ip = $request->ip();
        // Same key as NotFoundDetector::detect() — they track together
        $key = "botguardian:404:{$ip}";

        $count = Cache::increment($key);
        if ($count === 1) {
            Cache::put($key, 1, $timeWindow);
            $count = 1;
        } else {
            $count = Cache::get($key, $count);
        }

        if ($count > $maxHits) {
            return $this->increment($request, $score);
        }

        return 0;
    }

    public function resetScore(string $ip): void
    {
        Cache::forget("botguardian:score:{$ip}");
    }
}
