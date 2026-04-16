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
            new \Febryntara\LaravelBotGuardian\Detectors\NotFoundDetector(),
            new \Febryntara\LaravelBotGuardian\Detectors\LoginAttemptDetector(),
            new \Febryntara\LaravelBotGuardian\Detectors\EndpointRateLimiter(),
            new \Febryntara\LaravelBotGuardian\Detectors\BehavioralPatternDetector(),
        ];
    }

    /**
     * Get all detector instances (for external access like stats).
     */
    public function getDetectors(): array
    {
        return $this->detectors;
    }

    /**
     * Calculate total violation score for a request.
     */
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

    /**
     * Get the total accumulated score for this IP within the decay window.
     */
    public function getTotalScore(Request $request): int
    {
        $ip = $request->ip();
        $key = "botguardian:score:{$ip}";
        return Cache::get($key, 0);
    }

    /**
     * Increment the score for this IP within the decay window.
     * FIX: Use atomic increment to avoid race condition.
     */
    public function increment(Request $request, int $score): void
    {
        $ip = $request->ip();
        $key = "botguardian:score:{$ip}";
        $window = config('botguardian.score_decay_window', 300);

        $current = Cache::increment($key);
        if ($current === 1) {
            // First score — set the window
            Cache::put($key, $score, $window);
        } else {
            // Subsequent — add to existing, preserve expiry
            $existing = Cache::get($key, 0);
            Cache::put($key, $existing + $score, $window);
        }
    }

    /**
     * Reset score for an IP (e.g., on manual unblock).
     */
    public function resetScore(string $ip): void
    {
        Cache::forget("botguardian:score:{$ip}");
    }

    /**
     * Get current velocity count for an IP.
     */
    public function getVelocityCount(string $ip): int
    {
        return Cache::get("botguardian:velocity:{$ip}", 0);
    }

    /**
     * Get current 404 count for an IP.
     */
    public function getNotFoundCount(string $ip): int
    {
        return Cache::get("botguardian:404:{$ip}", 0);
    }

    /**
     * Get login attempt count for an IP.
     */
    public function getLoginAttemptCount(string $ip): int
    {
        return Cache::get("botguardian:login_attempts:{$ip}", 0);
    }
}
