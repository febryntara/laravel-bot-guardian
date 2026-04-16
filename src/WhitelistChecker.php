<?php

namespace Febryntara\LaravelBotGuardian;

use Illuminate\Support\Facades\Cache;
use Illuminate\Http\Request;

/**
 * Whitelist & Blacklist checker.
 * 
 * Whitelist: IPs/CIDRs that bypass ALL bot guardian checks entirely.
 * Blacklist: IPs/CIDRs that are immediately blocked without scoring.
 * 
 * Supports:
 * - Single IP: '192.168.1.1'
 * - CIDR notation: '10.0.0.0/8', '192.168.1.0/24'
 * - Pattern match: '192.168.*' (simple wildcard)
 * - Config file (static)
 * - Cache (dynamic, for runtime additions)
 * 
 * Order of precedence:
 *   1. Whitelist → pass through without any check
 *   2. Blacklist → immediate 403, no scoring
 *   3. Normal detection flow
 */
class WhitelistChecker
{
    public function isWhitelisted(string $ip): bool
    {
        if (! $this->isEnabled()) {
            return false;
        }

        $config = config('botguardian.whitelist.enabled', false);
        if (empty($config)) {
            return false;
        }

        // Check whitelist IPs from config
        if ($this->matchIp($ip, $this->getWhitelist())) {
            return true;
        }

        // Check dynamic whitelist from cache
        $dynamic = Cache::get('botguardian:whitelist', []);
        if ($this->matchIp($ip, $dynamic)) {
            return true;
        }

        return false;
    }

    public function isBlacklisted(string $ip): bool
    {
        if (! $this->isEnabled()) {
            return false;
        }

        $config = config('botguardian.blacklist.enabled', false);
        if (empty($config)) {
            return false;
        }

        // Check blacklist IPs from config
        if ($this->matchIp($ip, $this->getBlacklist())) {
            return true;
        }

        // Check dynamic blacklist from cache
        $dynamic = Cache::get('botguardian:blacklist', []);
        if ($this->matchIp($ip, $dynamic)) {
            return true;
        }

        return false;
    }

    /**
     * Add an IP to the dynamic whitelist (runtime).
     */
    public function whitelist(string $ip, int $ttl = 0): void
    {
        $key = 'botguardian:whitelist';
        $list = Cache::get($key, []);
        $list[] = $ip;
        if ($ttl > 0) {
            Cache::put($key, $list, $ttl);
        } else {
            Cache::forever($key, $list);
        }
    }

    /**
     * Add an IP to the dynamic blacklist (runtime).
     */
    public function blacklist(string $ip, int $ttl = 0): void
    {
        $key = 'botguardian:blacklist';
        $list = Cache::get($key, []);
        $list[] = $ip;
        if ($ttl > 0) {
            Cache::put($key, $list, $ttl);
        } else {
            Cache::forever($key, $list);
        }
    }

    /**
     * Remove an IP from dynamic whitelist.
     */
    public function unwhitelist(string $ip): void
    {
        $key = 'botguardian:whitelist';
        $list = Cache::get($key, []);
        $list = array_filter($list, fn($e) => $e !== $ip);
        Cache::forever($key, array_values($list));
    }

    /**
     * Remove an IP from dynamic blacklist.
     */
    public function unblacklist(string $ip): void
    {
        $key = 'botguardian:blacklist';
        $list = Cache::get($key, []);
        $list = array_filter($list, fn($e) => $e !== $ip);
        Cache::forever($key, array_values($list));
    }

    protected function isEnabled(): bool
    {
        return config('botguardian.whitelist.enabled', false)
            || config('botguardian.blacklist.enabled', false);
    }

    protected function getWhitelist(): array
    {
        return config('botguardian.whitelist.ips', []);
    }

    protected function getBlacklist(): array
    {
        return config('botguardian.blacklist.ips', []);
    }

    /**
     * Match IP against a list of patterns (IP, CIDR, wildcard).
     */
    protected function matchIp(string $ip, array $patterns): bool
    {
        foreach ($patterns as $pattern) {
            $pattern = trim($pattern);
            if (empty($pattern)) {
                continue;
            }

            // Exact match
            if ($pattern === $ip) {
                return true;
            }

            // CIDR match (IPv4)
            if (str_contains($pattern, '/')) {
                if ($this->cidrMatch($ip, $pattern)) {
                    return true;
                }
            }

            // Wildcard match (*)
            if (str_contains($pattern, '*')) {
                $regex = '/^' . str_replace(['.', '*'], ['\.', '.*'], $pattern) . '$/';
                if (preg_match($regex, $ip)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if IP is within CIDR range (IPv4 only).
     */
    protected function cidrMatch(string $ip, string $cidr): bool
    {
        if (! str_contains($cidr, '/')) {
            return $ip === $cidr;
        }

        [$subnet, $mask] = explode('/', $cidr);
        $mask = (int) $mask;

        if ($mask < 0 || $mask > 32) {
            return false;
        }

        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);

        if ($ipLong === false || $subnetLong === false) {
            return false;
        }

        $maskLong = -1 << (32 - $mask);
        return ($ipLong & $maskLong) === ($subnetLong & $maskLong);
    }
}
