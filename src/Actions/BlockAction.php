<?php

namespace Febryntara\LaravelBotGuardian\Actions;

use Illuminate\Support\Facades\Cache;
use Febryntara\LaravelBotGuardian\RecidivistBlocker;

class BlockAction
{
    protected RecidivistBlocker $recidivist;
    protected NotifyAction $notifyAction;

    public function __construct(RecidivistBlocker $recidivist, NotifyAction $notifyAction)
    {
        $this->recidivist = $recidivist;
        $this->notifyAction = $notifyAction;
    }

    /**
     * Block an IP temporarily or permanently.
     */
    public function execute(string $ip, bool $permanent = false, array $context = []): void
    {
        $blockKey = "botguardian:blocked:{$ip}";
        $duration = $permanent ? 0 : (config('botguardian.block_duration', 3600));

        if ($permanent) {
            Cache::forever($blockKey, true);
            Cache::forever("botguardian:permanent:{$ip}", true);
        } else {
            Cache::put($blockKey, true, $duration);
        }

        $this->recidivist->recordBlock($ip);

        if (! $permanent && $this->recidivist->shouldPermanentBlock($ip)) {
            $this->execute($ip, true, $context);
            return;
        }

        // Dispatch notification
        $totalScore = $context['total_score'] ?? config('botguardian.threshold', 100);
        $triggeredBy = $context['triggered_by'] ?? 'BotGuardian';
        $this->notifyAction->onBlock($ip, $totalScore, $triggeredBy, $context, $permanent);

        // Forward to telemetry if enabled
        $this->notifyAction->toTelemetry('botguardian.block', [
            'ip' => $ip,
            'permanent' => $permanent,
            'score' => $totalScore,
            'triggered_by' => $triggeredBy,
        ], 'warning');
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
        $activeCount = Cache::get('botguardian:blocked:count', 0);
        return $activeCount;
    }
}
