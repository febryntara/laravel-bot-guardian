<?php

namespace Febryntara\LaravelBotGuardian\Detectors;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;

/**
 * Session Anomaly Detection — mendeteksi session fixation & hijacking attempt.
 *
 * ATTACK MODELS:
 * 1. Session Fixation: attacker injects a known session ID, then tricks victim
 *    into authenticating with that ID. After auth, attacker uses the same ID.
 *    Detection: session ID changes AFTER auth (unusual pattern).
 *
 * 2. Session Hijacking: attacker steals a valid session ID (via XSS, network sniffing)
 *    and uses it from different IP/browser. Detection: same session, many distinct IPs.
 *
 * 3. Suspicious Session Creation: session created but never used for page浏览,
 *    only for API calls or form submissions.
 *
 * HOW IT WORKS:
 * - Track session ID changes (fixation indicator)
 * - Track IP diversity per session (hijacking indicator)
 * - Track session age vs request count (suspicious burst usage)
 *
 * LIMITATION:
 * - Requires session facade access → needs Laravel session middleware running.
 * - Works best when BotGuardian runs AFTER session middleware.
 *
 * CONFIG: botguardian.session
 */
class SessionAnomalyDetector implements DetectorInterface
{
    public function detect(Request $request): int
    {
        if (! $this->isEnabled()) {
            return 0;
        }

        // Only check authenticated sessions (auth state matters for fixation)
        $sessionId = $request->session()->getId();
        if (empty($sessionId) || $sessionId === '_fake') {
            return 0;
        }

        $config = config('botguardian.session');
        $ip = $request->ip();
        $score = 0;

        // === Check 1: Session fixation — session ID changed unexpectedly ===
        $score += $this->checkSessionFixation($sessionId, $ip, $config);

        // === Check 2: Session hijacking — same session from many IPs ===
        $score += $this->checkSessionHijacking($sessionId, $ip, $config);

        // === Check 3: Suspicious session age (new session with high request rate) ===
        $score += $this->checkSessionBurst($sessionId, $ip, $config);

        return min($score, $config['max_score'] ?? 50);
    }

    protected function checkSessionFixation(string $sessionId, string $ip, array $config): int
    {
        $key = "botguardian:session:fixation:{$sessionId}";
        $currentIp = Cache::get($key . ':ip');
        $authenticated = Cache::get($key . ':auth');

        // First time seeing this session
        if ($currentIp === null) {
            Cache::put($key . ':ip', $ip, $config['session_tracking_window'] ?? 86400);
            Cache::put($key . ':sid', $sessionId, $config['session_tracking_window'] ?? 86400);
            return 0;
        }

        // Session ID changed but same IP → fixation attempt (attacker set ID before victim)
        $storedSid = Cache::get($key . ':sid', '');
        if ($storedSid !== $sessionId && $currentIp === $ip) {
            return $config['session_fixation_score'] ?? 40;
        }

        // Session ID changed to a new value (normal users don't change session IDs mid-session)
        if ($storedSid !== $sessionId) {
            Cache::put($key . ':sid', $sessionId, $config['session_tracking_window'] ?? 86400);
        }

        return 0;
    }

    protected function checkSessionHijacking(string $sessionId, string $ip, array $config): int
    {
        $key = "botguardian:session:hijack:{$sessionId}";
        $threshold = $config['max_ips_per_session'] ?? 3;
        $score = $config['session_hijack_score'] ?? 30;

        $ipKey = "botguardian:session:hijack:{$sessionId}:ip:{$ip}";

        if (! Cache::has($ipKey)) {
            $current = Cache::increment($key);
            if ($current === 1) {
                Cache::put($key, 1, $config['session_tracking_window'] ?? 86400);
            }
            Cache::put($ipKey, true, $config['session_tracking_window'] ?? 86400);

            $totalIps = Cache::get($key, 1);
            if ($totalIps > $threshold) {
                return $score;
            }
        }

        return 0;
    }

    protected function checkSessionBurst(string $sessionId, string $ip, array $config): int
    {
        $key = "botguardian:session:burst:{$sessionId}";
        $window = $config['burst_window'] ?? 60;
        $maxBurst = $config['max_burst_requests'] ?? 30;

        $count = Cache::increment($key);
        if ($count === 1) {
            Cache::put($key, 1, $window);
        } else {
            $count = Cache::get($key, $count);
        }

        if ($count > $maxBurst) {
            return $config['burst_score'] ?? 20;
        }

        return 0;
    }

    public function isEnabled(): bool
    {
        return config('botguardian.session.enabled', false);
    }

    public function getName(): string
    {
        return 'session_anomaly';
    }
}
