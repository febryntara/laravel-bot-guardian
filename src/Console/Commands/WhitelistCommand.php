<?php

namespace Febryntara\LaravelBotGuardian\Console\Commands;

use Febryntara\LaravelBotGuardian\Actions\BlockAction;
use Illuminate\Console\Command;

class WhitelistCommand extends Command
{
    protected $signature = 'botguardian:whitelist {ip : The IP address to whitelist}';

    protected $description = 'Add an IP to the BotGuardian whitelist';

    public function handle(): int
    {
        $ip = trim($this->argument('ip'));

        if (! filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->error("Invalid IP address: {$ip}");
            return self::FAILURE;
        }

        $whitelist = config('botguardian.whitelist.ips', []);
        $enabled = config('botguardian.whitelist.enabled', false);

        if (in_array($ip, $whitelist, true)) {
            $this->warn("IP {$ip} is already in the whitelist.");
            return self::SUCCESS;
        }

        $whitelist[] = $ip;
        $this->updateConfig('botguardian.whitelist.ips', $whitelist);

        if (! $enabled) {
            $this->warn("Note: whitelist is currently disabled. Enable it in config/botguardian.php.");
        }

        $this->info("✓ IP {$ip} added to whitelist. (" . count($whitelist) . " total)");

        // Auto-unblock if currently blocked
        try {
            $blockAction = app(BlockAction::class);
            if ($blockAction->isBlocked($ip)) {
                $blockAction->unblock($ip);
                $this->info("✓ IP {$ip} was also unblocked (it was previously blocked).");
            }
        } catch (\Throwable $e) {
            // ignore
        }

        return self::SUCCESS;
    }

    protected function updateConfig(string $key, mixed $value): void
    {
        $path = config_path('botguardian.php');
        if (! file_exists($path)) {
            $this->error("Config file not found: {$path}");
            return;
        }

        $config = include $path;
        data_set($config, str_replace('botguardian.', '', $key), $value);

        $content = "<?php\n\nreturn " . var_export($config, true) . ";\n";
        file_put_contents($path, $content);
    }
}
