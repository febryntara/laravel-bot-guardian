<?php

namespace Febryntara\LaravelBotGuardian;

use Illuminate\Support\Facades\Cache;

/**
 * Track how many times an IP has been blocked.
 * If blocked more than N times → escalate to permanent block.
 *
 * This prevents decay-window exploitation:
 * attacker hits ~80 score, waits 5 min, score resets, repeat.
 * With RecidivistBlocker, after N blocks the IP gets permanently banned
 * (until manually unblocked via artisan command).
 */
class RecidivistBlocker
{
    /**
     * Increment block count for an IP.
     */
    public function recordBlock(string $ip): int
    {
        $key = "botguardian:block_count:{$ip}";
        $count = Cache::increment($key);
        $maxBlocks = config('botguardian.recidivist.max_blocks_before_permanent', 3);
        $window = config('botguardian.recidivist.count_window', 86400); // 24 hours

        // Set expiry so count naturally resets after window
        if ($count === 1) {
            Cache::put($key, 1, $window);
        }

        return $count;
    }

    /**
     * Check if IP should be permanently blocked (repeat offender).
     */
    public function shouldPermanentBlock(string $ip): bool
    {
        $config = config('botguardian.recidivist');

        if (empty($config['enabled'])) {
            return false;
        }

        $key = "botguardian:block_count:{$ip}";
        $count = Cache::get($key, 0);
        $threshold = $config['max_blocks_before_permanent'] ?? 3;

        return $count >= $threshold;
    }

    /**
     * Get block count for an IP.
     */
    public function getBlockCount(string $ip): int
    {
        $key = "botguardian:block_count:{$ip}";
        return Cache::get($key, 0);
    }

    /**
     * Reset block count (e.g., after manual unblock).
     */
    public function resetBlockCount(string $ip): void
    {
        $key = "botguardian:block_count:{$ip}";
        Cache::forget($key);
    }
}
