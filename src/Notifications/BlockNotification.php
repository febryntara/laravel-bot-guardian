<?php

namespace Febryntara\LaravelBotGuardian\Notifications;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Log;

class BlockNotification
{
    /**
     * Send block notification via email and/or webhook.
     *
     * @param string $ip
     * @param int $totalScore
     * @param string $triggeredBy       e.g. "VelocityDetector"
     * @param array $context            request data (UA, path, etc.)
     * @param bool $permanent
     */
    public function send(
        string $ip,
        int $totalScore,
        string $triggeredBy,
        array $context = [],
        bool $permanent = false
    ): void {
        $config = config('botguardian.notifications');

        if (! empty($config['email']['enabled'])) {
            $this->sendEmail($ip, $totalScore, $triggeredBy, $context, $permanent);
        }

        if (! empty($config['webhook']['enabled']) && ! empty($config['webhook']['url'])) {
            $this->sendWebhook($ip, $totalScore, $triggeredBy, $context, $permanent);
        }
    }

    // -------------------------------------------------------------------------
    // Email
    // -------------------------------------------------------------------------

    protected function sendEmail(
        string $ip,
        int $totalScore,
        string $triggeredBy,
        array $context,
        bool $permanent
    ): void {
        $cfg = config('botguardian.notifications.email');
        $prefix = $cfg['subject_prefix'] ?? '[BotGuardian]';
        $recipients = $cfg['to'] ?? [];

        if (empty($recipients)) {
            return;
        }

        $type = $permanent ? '🚨 PERMANENT BLOCK' : '⚠️ BOT BLOCKED';
        $subject = "{$prefix} {$type} — IP: {$ip}";

        $lines = [
            "{$type}",
            "IP Address : {$ip}",
            "Total Score: {$totalScore}",
            "Triggered  : {$triggeredBy}",
            "Blocked At : " . now()->toDateTimeString(),
            "",
            "--- Request Context ---",
        ];

        $lines[] = "URL        : " . ($context['url'] ?? 'N/A');
        $lines[] = "User-Agent: " . ($context['user_agent'] ?? 'N/A');
        $lines[] = "Method     : " . ($context['method'] ?? 'N/A');
        $lines[] = "Referer    : " . ($context['referer'] ?? 'N/A');

        if (! empty($context['detector_scores'])) {
            $lines[] = "";
            $lines[] = "--- Detector Breakdown ---";
            foreach ($context['detector_scores'] as $detector => $score) {
                $lines[] = "  {$detector}: {$score}";
            }
        }

        try {
            Mail::raw(implode("\n", $lines), function ($message) use ($recipients, $subject) {
                $message->to($recipients)
                    ->subject($subject);
            });
        } catch (\Throwable $e) {
            Log::error('[BotGuardian] Failed to send block notification email: ' . $e->getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // Webhook
    // -------------------------------------------------------------------------

    protected function sendWebhook(
        string $ip,
        int $totalScore,
        string $triggeredBy,
        array $context,
        bool $permanent
    ): void {
        $cfg = config('botguardian.notifications.webhook');
        $url = $cfg['url'];

        $payload = [
            'event' => 'botguardian.block',
            'type' => $permanent ? 'permanent' : 'temporary',
            'timestamp' => now()->toIso8601String(),
            'ip' => $ip,
            'total_score' => $totalScore,
            'triggered_by' => $triggeredBy,
            'block_duration' => $permanent ? -1 : (config('botguardian.block_duration', 3600)),
        ];

        if (! empty($cfg['include_context'])) {
            $payload['context'] = [
                'url' => $context['url'] ?? null,
                'user_agent' => $context['user_agent'] ?? null,
                'method' => $context['method'] ?? null,
                'referer' => $context['referer'] ?? null,
                'path' => $context['path'] ?? null,
                'detector_scores' => $context['detector_scores'] ?? [],
            ];
        }

        // HMAC signature if secret is set
        $headers = ['Content-Type' => 'application/json'];
        if (! empty($cfg['secret'])) {
            $signature = hash_hmac('sha256', json_encode($payload), $cfg['secret']);
            $headers['X-BotGuardian-Signature'] = $signature;
        }

        $retries = (int) ($cfg['retry'] ?? 3);
        $timeout = (int) ($cfg['timeout'] ?? 10);
        $attempt = 0;

        while ($attempt < $retries) {
            $attempt++;
            try {
                Http::timeout($timeout)
                    ->withHeaders($headers)
                    ->post($url, $payload);

                return; // success
            } catch (\Throwable $e) {
                Log::warning("[BotGuardian] Webhook attempt {$attempt}/{$retries} failed: " . $e->getMessage());

                if ($attempt >= $retries) {
                    Log::error('[BotGuardian] All webhook retry attempts exhausted for IP: ' . $ip);
                }
            }
        }
    }
}
