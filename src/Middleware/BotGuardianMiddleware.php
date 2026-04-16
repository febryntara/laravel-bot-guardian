<?php

namespace Febryntara\LaravelBotGuardian\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Febryntara\LaravelBotGuardian\Scorer\BotScoreCalculator;
use Febryntara\LaravelBotGuardian\WhitelistChecker;
use Febryntara\LaravelBotGuardian\Actions\BlockAction;
use Febryntara\LaravelBotGuardian\RecidivistBlocker;

class BotGuardianMiddleware
{
    protected BotScoreCalculator $scorer;
    protected WhitelistChecker $whitelist;
    protected BlockAction $blockAction;
    protected RecidivistBlocker $recidivist;

    public function __construct(
        BotScoreCalculator $scorer,
        WhitelistChecker $whitelist,
        BlockAction $blockAction,
        RecidivistBlocker $recidivist
    ) {
        $this->scorer = $scorer;
        $this->whitelist = $whitelist;
        $this->blockAction = $blockAction;
        $this->recidivist = $recidivist;
    }

    public function handle(Request $request, Closure $next)
    {
        if (! config('botguardian.enabled', true)) {
            return $next($request);
        }

        $ip = $request->ip();

        // === WHITELIST: bypass all checks ===
        if ($this->whitelist->isWhitelisted($ip)) {
            return $next($request);
        }

        // === BLACKLIST: immediate block, no scoring ===
        if ($this->whitelist->isBlacklisted($ip)) {
            return $this->blockResponse($request, $ip, 'blacklisted');
        }

        // === Already blocked? Return blocked response ===
        if ($this->isBlocked($ip)) {
            return $this->blockResponse($request, $ip);
        }

        // === FIX #1: Pending block from terminate() — block on NEXT request ===
        // When terminate() detects threshold-exceeding 404 score, it sets a pending
        // flag (can't block current request because response already sent).
        // Check it here — before forwarding to application.
        if (Cache::has("botguardian:pending_block:{$ip}")) {
            Cache::forget("botguardian:pending_block:{$ip}");
            return $this->doBlock($request, $ip, '404_spam');
        }

        // === FIX #1: Atomic scoring — score → increment → check ===
        // increment() returns the NEW total atomically.
        // No TOCTOU race because increment is atomic and check is AFTER it.
        $score = $this->scorer->calculate($request);

        if ($score > 0) {
            $total = $this->scorer->increment($request, $score);

            if ($total >= config('botguardian.threshold', 100)) {
                return $this->doBlock($request, $ip, 'score_threshold');
            }
        }

        return $next($request);
    }

    /**
     * FIX #7: terminate() — post-response 404 detection.
     *
     * Response status code known here (not in handle()). For actual HTTP 404
     * responses, call increment404() which adds to total score. If threshold is
     * exceeded, set a PENDING block flag — the current request already has its
     * response committed, so the next request from this IP will be blocked.
     */
    public function terminate(Request $request, Response $response): void
    {
        if (! config('botguardian.enabled', true)) {
            return;
        }

        $ip = $request->ip();

        if ($this->whitelist->isWhitelisted($ip) || $this->isBlocked($ip)) {
            return;
        }

        if ($response->getStatusCode() === 404) {
            $scoreAdded = $this->scorer->increment404($request);

            if ($scoreAdded > 0) {
                // Score was added AND threshold was exceeded.
                // Current response already sent — set pending block for next request.
                Cache::put("botguardian:pending_block:{$ip}", true, config('botguardian.block_duration', 3600));
            }
        }
    }

    /**
     * Actually perform the block. Separated so handle() and terminate() can both call it.
     */
    protected function doBlock(Request $request, string $ip, string $reason): Response
    {
        $total = $this->scorer->getTotalScore($request);

        if ($this->recidivist->shouldPermanentBlock($ip)) {
            $this->blockAction->execute($ip, true);
            $this->logBlock($ip, $total, $request, 'permanent_recidivist');
        } else {
            $this->blockAction->execute($ip, false);
            $this->logBlock($ip, $total, $request, $reason);
        }

        return $this->blockResponse($request, $ip);
    }

    protected function isBlocked(string $ip): bool
    {
        return $this->blockAction->isBlocked($ip);
    }

    protected function blockResponse(Request $request, string $ip, string $reason = 'blocked'): Response
    {
        $view = config('botguardian.block_view', 'botguardian::blocked');
        $viewExists = view()->exists($view);

        if ($viewExists && $reason !== 'blacklisted') {
            return response()->view($view, [
                'ip' => $ip,
                'permanent' => $this->blockAction->isPermanentBlocked($ip),
                'reason' => $reason,
            ], 403);
        }

        $message = match ($reason) {
            'blacklisted' => 'Access denied.',
            default => $this->blockAction->isPermanentBlocked($ip)
                ? 'Access permanently blocked.'
                : 'Access has been temporarily blocked due to suspicious activity.',
        };

        return response($message, 403);
    }

    protected function logBlock(string $ip, int $totalScore, Request $request, string $blockType): void
    {
        if (! config('botguardian.log_enabled', true)) {
            return;
        }

        Log::warning('Bot Guardian: IP blocked', [
            'ip' => $ip,
            'score' => $totalScore,
            'block_type' => $blockType,
            'user_agent' => $request->userAgent(),
            'url' => $request->fullUrl(),
            'method' => $request->method(),
        ]);
    }
}
