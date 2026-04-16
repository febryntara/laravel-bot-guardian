<?php

namespace Febryntara\LaravelBotGuardian\Console\Commands;

use Febryntara\LaravelBotGuardian\Scorer\BotScoreCalculator;
use Febryntara\LaravelBotGuardian\RecidivistBlocker;
use Illuminate\Support\Facades\Cache;
use Illuminate\Console\Command;

class StatsCommand extends Command
{
    protected $signature = 'botguardian:stats
                            {--json : Output as JSON}
                            {--top=10 : Show top N suspicious IPs}';

    protected $description = 'Show BotGuardian detection statistics';

    public function handle(BotScoreCalculator $calculator, RecidivistBlocker $recidivist): int
    {
        $asJson = (bool) $this->option('json');
        $topN = (int) $this->option('top');

        $stats = $this->buildStats($calculator, $recidivist, $topN);

        if ($asJson) {
            $this->line(json_encode($stats, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
            return self::SUCCESS;
        }

        $this->showTextStats($stats);

        return self::SUCCESS;
    }

    protected function buildStats(BotScoreCalculator $calculator, RecidivistBlocker $recidivist, int $topN): array
    {
        $enabledDetectors = collect($calculator->getDetectors())
            ->filter(fn($d) => $d->isEnabled())
            ->map(fn($d) => (new \ReflectionClass($d))->getShortName())
            ->values()
            ->toArray();

        // Try to collect cache-based stats
        $store = Cache::getStore();
        $prefix = 'botguardian:';

        return [
            'package' => 'laravel-bot-guardian',
            'version' => config('botguardian.version', '1.x'),
            'enabled' => config('botguardian.enabled', true),
            'threshold' => config('botguardian.threshold', 100),
            'block_duration' => config('botguardian.block_duration', 3600),
            'active_detectors' => $enabledDetectors,
            'notifications' => [
                'email' => config('botguardian.notifications.email.enabled', false),
                'webhook' => config('botguardian.notifications.webhook.enabled', false),
            ],
            'telemetry' => config('botguardian.telemetry.enabled', false),
            'recidivist' => [
                'enabled' => config('botguardian.recidivist.enabled', true),
                'max_blocks' => config('botguardian.recidivist.max_blocks_before_permanent', 3),
                'window' => config('botguardian.recidivist.count_window', 86400),
            ],
            'whitelist' => [
                'enabled' => config('botguardian.whitelist.enabled', false),
                'ip_count' => count(config('botguardian.whitelist.ips', [])),
            ],
            'blacklist' => [
                'enabled' => config('botguardian.blacklist.enabled', false),
                'ip_count' => count(config('botguardian.blacklist.ips', [])),
            ],
        ];
    }

    protected function showTextStats(array $stats): void
    {
        $this->newLine();
        $this->info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        $this->info("              BotGuardian Stats                ");
        $this->info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        $this->newLine();

        $status = $stats['enabled'] ? '<fg=green>ENABLED</>' : '<fg=red>DISABLED</>';
        $this->line("  Status          : {$status}");
        $this->line("  Threshold       : {$stats['threshold']}");
        $this->line("  Block Duration  : {$stats['block_duration']}s");
        $this->newLine();

        $this->info("  Active Detectors (" . count($stats['active_detectors']) . "):");
        foreach ($stats['active_detectors'] as $detector) {
            $this->line("    • {$detector}");
        }
        $this->newLine();

        $this->info("  Notifications:");
        $this->line("    Email   : " . ($stats['notifications']['email'] ? '<fg=green>ON</>' : '<fg=red>OFF</>'));
        $this->line("    Webhook : " . ($stats['notifications']['webhook'] ? '<fg=green>ON</>' : '<fg=red>OFF</>'));
        $this->line("    Telemetry: " . ($stats['telemetry'] ? '<fg=green>ON</>' : '<fg=red>OFF</>'));
        $this->newLine();

        $this->info("  Recidivist:");
        $this->line("    Max blocks before permanent: {$stats['recidivist']['max_blocks']}");
        $this->line("    Window: {$stats['recidivist']['window']}s");
        $this->newLine();

        $wlCount = $stats['whitelist']['ip_count'];
        $blCount = $stats['blacklist']['ip_count'];
        $this->line("  Whitelist: {$wlCount} IPs (" . ($stats['whitelist']['enabled'] ? '<fg=green>ON</>' : '<fg=red>OFF</>') . ")");
        $this->line("  Blacklist: {$blCount} IPs (" . ($stats['blacklist']['enabled'] ? '<fg=green>ON</>' : '<fg=red>OFF</>') . ")");
        $this->newLine();
        $this->info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    }
}
