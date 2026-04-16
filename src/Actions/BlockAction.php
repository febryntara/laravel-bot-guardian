<?php

namespace Febryntara\LaravelBotGuardian\Actions;

use Illuminate\Support\Facades\Cache;
use Febryntara\LaravelBotGuardian\RecidivistBlocker;

class BlockAction
{
    protected RecidivistBlocker $recidivist;

    public function __construct(RecidivistBlocker $recidivist)
    {
        $this->recidivist = $recidivist;
    }

    /**
     * Block an IP temporarily or permanently.
     */
    public function execute(string $ip, bool $permanent = false): void
    {
        $blockKey = "botguardian:blocked:{$ip}";
        $duration = $permanent ? 0 : (config('botguardian.block_duration', 3600));

        if ($permanent) {
            Cache::forever($blockKey, true);
            // Also record as permanent in a separate key for identification
            Cache::forever("botguardian:permanent:{$ip}", true);
        } else {
            Cache::put($blockKey, true, $duration);
        }

        // Record for recidivist tracking
        $this->recidivist->recordBlock($ip);

        // Escalate to permanent if recidivist threshold reached
        if (! $permanent && $this->recidivist->shouldPermanentBlock($ip)) {
            $this->execute($ip, true);
        }
    }

    /**
     * Check if IP is currently blocked.
     */
    public function isBlocked(string $ip): bool
    {
        $blockKey = "botguardian:blocked:{$ip}";
        return Cache::has($blockKey);
    }

    /**
     * Check if IP is permanently blocked.
     */
    public function isPermanentBlocked(string $ip): bool
    {
        return Cache::has("botguardian:permanent:{$ip}");
    }

    /**
     * Manually unblock an IP (temporary).
     */
    public function unblock(string $ip): void
    {
        Cache::forget("botguardian:blocked:{$ip}");
        Cache::forget("botguardian:permanent:{$ip}");
        $this->recidivist->resetBlockCount($ip);
    }

    /**
     * Permanently block an IP (until manual unblock).
     */
    public function blockPermanent(string $ip): void
    {
        $this->execute($ip, true);
    }

    /**
     * Get remaining block time in seconds. Returns -1 if permanent.
     */
    public function getRemainingTime(string $ip): int
    {
        if ($this->isPermanentBlocked($ip)) {
            return -1;
        }
        $blockKey = "botguardian:blocked:{$ip}";
        $expiresAt = Cache::getStore()->get($blockKey . ':expiresAt');
        if (! $expiresAt) {
            return 0;
        }
        $remaining = $expiresAt - time();
        return max(0, $remaining);
    }

    /**
     * Count how many IPs are currently blocked.
     */
    public function getBlockedCount(): int
    {
        $store = Cache::getStore();
        if (method_exists($store, 'getFlatKey')) {
            // Redis-backed or similar
            $count = 0;
            // This is implementation-specific; for now return from a tracking key
            $activeCount = Cache::get('botguardian:blocked:count', 0);
            return $activeCount;
        }
        return 0;
    }
}
