<?php

namespace Febryntara\LaravelBotGuardian\Actions;

use Illuminate\Support\Facades\Log;

class LogAction
{
    /**
     * Log a bot detection event.
     *
     * @param string $ip       The IP address that was flagged
     * @param string $detector Name of the detector that triggered
     * @param int    $score    Score assigned
     * @param array  $context  Additional request context
     */
    public function execute(string $ip, string $detector, int $score, array $context = []): void
    {
        if (! config('botguardian.log_enabled', true)) {
            return;
        }

        $message = sprintf(
            'Bot Guardian: %s — Score: %d — IP: %s',
            $detector,
            $score,
            $ip
        );

        if (config('botguardian.log_to_database', false)) {
            // Phase 2: simpan ke tabel bot_events
            Log::info($message, $context);
        } else {
            Log::warning($message, $context);
        }
    }

    /**
     * Log a block event (IP sudah kena block).
     */
    public function logBlock(string $ip, int $totalScore, array $context = []): void
    {
        if (! config('botguardian.log_enabled', true)) {
            return;
        }

        $message = sprintf(
            'Bot Guardian: BLOCKED — IP: %s — Total Score: %d',
            $ip,
            $totalScore
        );

        Log::warning($message, $context);
    }
}
