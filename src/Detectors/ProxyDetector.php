<?php

namespace Febryntara\LaravelBotGuardian\Detectors;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

/**
 * Proxy / VPN / TOR detection via HTTP header chain anomalies.
 *
 * No single header definitively proves proxy use — instead we detect SUSPICIOUS
 * combinations that indicate anonymity services:
 *
 * 1. X-Forwarded-For chain too long (3+ hops = multiple proxies / transparent proxy chain)
 * 2. X-Forwarded-For contains private/internal IP (proxy misconfiguration or spoofing)
 * 3. X-Real-IP present but X-Forwarded-For absent (poorly configured proxy)
 * 4. Via header present (explicit proxy indicator)
 * 5. X-Forwarded-For chain broken: rightmost IP is private (spoofed chain)
 * 6. Too many distinct IPs from same /24 subnet using same request fingerprint
 *
 * This detector is PROBABILISTIC, not definitive. Tune thresholds to balance
 * false positives (corporate proxies behind CDN) vs false negatives.
 *
 * CONFIG: botguardian.proxy
 */
class ProxyDetector implements DetectorInterface
{
    protected array $privateBlocks = [
        '10.', '172.16.', '172.17.', '172.18.', '172.19.',
        '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
        '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
        '172.30.', '172.31.', '192.168.', '127.', '0.',
    ];

    public function detect(Request $request): int
    {
        if (! $this->isEnabled()) {
            return 0;
        }

        $config = config('botguardian.proxy');
        $score = 0;

        $xff = $request->header('X-Forwarded-For', '');
        $xri = $request->header('X-Real-IP', '');
        $via = $request->header('Via', '');
        $fwd = $request->header('Forwarded', '');
        $ip = $request->ip();

        // === Check 1: Via header (explicit proxy indicator) ===
        if (! empty($via)) {
            $score += $config['via_header_score'] ?? 25;
        }

        // === Check 2: X-Forwarded-For chain analysis ===
        if (! empty($xff)) {
            $parts = array_map('trim', explode(',', $xff));

            // Chain too long — likely proxy chain or anonymity network
            $hops = count($parts);
            if ($hops >= ($config['max_xff_hops'] ?? 3)) {
                $score += $config['xff_too_many_hops_score'] ?? 20;
            }

            // Any hop is a private IP — suspicious
            foreach ($parts as $hop) {
                if ($this->isPrivateIp($hop)) {
                    $score += $config['xff_private_ip_score'] ?? 30;
                    break;
                }
            }

            // XFF present but X-Real-IP missing (some proxies only set one)
            if (empty($xri) && $hops >= 2) {
                $score += $config['xff_without_xri_score'] ?? 10;
            }

            // Rightmost IP in chain should be the outermost — if it's private, chain is spoofed
            $rightmost = end($parts);
            if ($this->isPrivateIp($rightmost)) {
                $score += $config['xff_spoofed_chain_score'] ?? 35;
            }

            // Rightmost IP matches our direct IP (XFF is spoofed with client's own IP)
            if ($rightmost === $ip && $hops > 1) {
                $score += $config['xff_matches_direct_ip_score'] ?? 25;
            }
        }

        // === Check 3: X-Real-IP without X-Forwarded-For ===
        // Could indicate a single-proxy setup OR forged header
        if (! empty($xri) && empty($xff)) {
            $score += $config['xri_alone_score'] ?? 15;
        }

        // === Check 4: X-Real-IP is private ===
        if (! empty($xri) && $this->isPrivateIp($xri)) {
            $score += $config['xri_private_ip_score'] ?? 30;
        }

        // === Check 5: Forwarded header (RFC 7239) ===
        if (! empty($fwd)) {
            // Parse Forwarded: host=...; for=...; by=...
            if (preg_match('/for=(\S+)/i', $fwd, $m)) {
                $forIp = trim($m[1], '"[]');
                // Check for= obfuscated or private (TOR uses obfuscated)
                if ($this->isPrivateIp($forIp) || str_contains($forIp, '_')) {
                    $score += $config['forwarded_private_score'] ?? 30;
                }
            }
        }

        // === Check 6: Suspicious request timing (proxy chain introduces latency variation) ===
        // Not implemented here — use BehavioralPatternDetector for timing analysis.

        return min($score, $config['max_score'] ?? 50);
    }

    protected function isPrivateIp(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return true;
        }
        return false;
    }

    public function isEnabled(): bool
    {
        return config('botguardian.proxy.enabled', false);
    }

    public function getName(): string
    {
        return 'proxy';
    }
}
