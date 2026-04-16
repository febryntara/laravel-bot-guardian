<?php

namespace Febryntara\LaravelBotGuardian\Actions;

use Febryntara\LaravelBotGuardian\Notifications\BlockNotification;

class NotifyAction
{
    protected BlockNotification $notification;

    public function __construct(BlockNotification $notification)
    {
        $this->notification = $notification;
    }

    /**
     * Dispatch notification when an IP is blocked.
     */
    public function onBlock(
        string $ip,
        int $totalScore,
        string $triggeredBy,
        array $context = [],
        bool $permanent = false
    ): void {
        $this->notification->send($ip, $totalScore, $triggeredBy, $context, $permanent);
    }

    /**
     * Dispatch notification when an attack pattern is detected (score exceeds threshold).
     * Fires before actual block, useful for real-time alerting.
     */
    public function onDetection(
        string $ip,
        int $totalScore,
        string $triggeredBy,
        array $context = []
    ): void {
        $cfg = config('botguardian.notifications');

        // Only notify on detection if email or webhook is enabled
        $shouldNotify = ! empty($cfg['email']['enabled']) || ! empty($cfg['webhook']['enabled']);
        if (! $shouldNotify) {
            return;
        }

        // Add detector scores to context
        if (isset($context['detector_scores']) && is_array($context['detector_scores'])) {
            $context['detector_scores'] = $context['detector_scores'];
        }

        $this->notification->send($ip, $totalScore, $triggeredBy, $context, false);
    }

    /**
     * Try sending to telemetry logger if package is installed.
     * Gracefully does nothing if package is not available.
     */
    public function toTelemetry(string $event, array $data = [], string $level = 'info'): void
    {
        if (! config('botguardian.telemetry.enabled', false)) {
            return;
        }

        if (! class_exists('Febryntara\TelemetryLogger\TelemetryLogger')) {
            return;
        }

        try {
            $logger = app('Febryntara\TelemetryLogger\TelemetryLogger');
            $logger->logEvent($event, $data, $level);
        } catch (\Throwable $e) {
            // Telemetry logger is optional — silent failure
        }
    }
}
