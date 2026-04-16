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

        // === Run all detectors ===
        $score = $this->scorer->calculate($request);

        if ($score >= config('botguardian.threshold', 100)) {
            // Accumulate score
            $this->scorer->increment($request, $score);
            $total = $this->scorer->getTotalScore($request);

            if ($total >= config('botguardian.threshold', 100)) {
                // === RECIDIVIST: escalate to permanent if repeat offender ===
                if ($this->recidivist->shouldPermanentBlock($ip)) {
                    $this->blockAction->execute($ip, true);
                    $this->logBlock($ip, $total, $request, 'permanent_recidivist');
                } else {
                    $this->blockAction->execute($ip, false);
                    $this->logBlock($ip, $total, $request, 'temporary');
                }

                return $this->blockResponse($request, $ip);
            }
        }

        return $next($request);
    }

    protected function isBlocked(string $ip): bool
    {
        return $this->blockAction->isBlocked($ip);
    }

    protected function blockResponse(Request $request, string $ip, string $reason = 'blocked'): Response
    {
        if ($reason !== 'blacklisted') {
            $view = config('botguardian.block_view', 'botguardian::blocked');
            $viewExists = view()->exists($view);

            if ($viewExists) {
                return response()->view($view, [
                    'ip' => $ip,
                    'permanent' => $this->blockAction->isPermanentBlocked($ip),
                    'reason' => $reason,
                ], 403);
            }
        }

        // Fallback plain response
        $message = $reason === 'blacklisted'
            ? 'Access denied.'
            : 'Access has been temporarily blocked due to suspicious activity.';

        if ($this->blockAction->isPermanentBlocked($ip)) {
            $message = 'Access permanently blocked.';
        }

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
