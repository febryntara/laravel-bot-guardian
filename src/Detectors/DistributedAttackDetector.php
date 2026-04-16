<?php

namespace Febryntara\LaravelBotGuardian\Detectors;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

/**
 * Distributed Attack Detection — mendeteksi serangan dari banyak IP sekaligus.
 *
 * ATTACK MODEL:
 * Botnet / proxy farm: 1000 IP × 1 req/IP = 1000 req total.
 * Tidak ada IP yang kena velocity detector karena tiap IP < threshold.
 * Tapi request yang направлены ke satu endpoint (misal login) sangat mencurigakan.
 *
 * DETECTION STRATEGY:
 * 1. Request fingerprint: hash(UA + Accept + Accept-Language + Accept-Encoding)
 * 2. Track how many DISTINCT IPs share the same fingerprint in a time window.
 *    - Normal traffic: many users, same fingerprint → few IPs per fingerprint
 *    - Botnet: identical bot UA, many IPs → many IPs per fingerprint
 * 3. Score based on IP count per fingerprint cluster.
 *
 * 2. Endpoint concentration: many IPs targeting the same sensitive endpoint.
 *    - Normal: IPs spread across many endpoints
 *    - Attack: IPs concentrate on login/password/reset endpoint
 *
 * CONFIG: botguardian.distributed
 */
class DistributedAttackDetector implements DetectorInterface
{
    public function detect(Request $request): int
    {
        if (! $this->isEnabled()) {
            return 0;
        }

        $config = config('botguardian.distributed');
        $score = 0;

        $ip = $request->ip();
        $path = '/' . ltrim($request->path(), '/');
        $fingerprint = $this->buildFingerprint($request);

        // === Check 1: Same fingerprint, many IPs (botnet with identical UA) ===
        $fingerprintScore = $this->checkFingerprintCluster($ip, $fingerprint, $config);
        $score += $fingerprintScore;

        // === Check 2: Same endpoint, many IPs (targeted attack on one URL) ===
        $endpointScore = $this->checkEndpointConcentration($ip, $path, $config);
        $score += $endpointScore;

        return min($score, $config['max_score'] ?? 60);
    }

    /**
     * Build request fingerprint from elements that bots tend to keep identical
     * across their fleet.
     */
    protected function buildFingerprint(Request $request): string
    {
        $parts = [
            $request->header('User-Agent') ?? '',
            $request->header('Accept', ''),
            $request->header('Accept-Language', ''),
            $request->header('Accept-Encoding', ''),
        ];

        return md5(implode('|', $parts));
    }

    protected function checkFingerprintCluster(string $ip, string $fingerprint, array $config): int
    {
        $window = $config['window'] ?? 120;
        $threshold = $config['ips_per_fingerprint'] ?? 10;
        $scorePerIp = $config['score_per_ip'] ?? 2;

        $key = "botguardian:dist:fp:{$fingerprint}";

        // Add current IP to the fingerprint's IP set
        $ipKey = "botguardian:dist:fp:{$fingerprint}:ip:{$ip}";
        $alreadyTracked = Cache::has($ipKey);

        if (! $alreadyTracked) {
            $current = Cache::increment($key);
            if ($current === 1) {
                Cache::put($key, 1, $window);
            }
            Cache::put($ipKey, true, $window);
        }

        $totalIps = Cache::get($key, 0);

        if ($totalIps > $threshold) {
            // Calculate score based on how many IPs beyond the threshold
            $excess = $totalIps - $threshold;
            return min($excess * $scorePerIp, $config['max_fingerprint_score'] ?? 30);
        }

        return 0;
    }

    protected function checkEndpointConcentration(string $ip, string $path, array $config): int
    {
        $window = $config['endpoint_window'] ?? 300;
        $sensitivePatterns = $config['sensitive_patterns'] ?? [
            'login', 'auth', 'password', 'reset', 'admin',
            'api/auth', 'api/login', 'api/reset',
        ];

        // Only track sensitive endpoints
        $isSensitive = false;
        foreach ($sensitivePatterns as $pattern) {
            if (str_contains($path, $pattern)) {
                $isSensitive = true;
                break;
            }
        }

        if (! $isSensitive) {
            return 0;
        }

        $threshold = $config['ips_per_endpoint'] ?? 20;
        $scorePerIp = $config['score_per_ip'] ?? 1;

        $endpointKey = "botguardian:dist:ep:" . md5($path);
        $ipKey = "botguardian:dist:ep:" . md5($path) . ":ip:{$ip}";

        if (! Cache::has($ipKey)) {
            $current = Cache::increment($endpointKey);
            if ($current === 1) {
                Cache::put($endpointKey, 1, $window);
            }
            Cache::put($ipKey, true, $window);
        }

        $totalIps = Cache::get($endpointKey, 0);

        if ($totalIps > $threshold) {
            $excess = $totalIps - $threshold;
            return min($excess * $scorePerIp, $config['max_endpoint_score'] ?? 30);
        }

        return 0;
    }

    public function isEnabled(): bool
    {
        return config('botguardian.distributed.enabled', false);
    }

    public function getName(): string
    {
        return 'distributed_attack';
    }
}
