<?php

namespace Febryntara\LaravelBotGuardian\Console\Commands;

use Febryntara\LaravelBotGuardian\Actions\BlockAction;
use Illuminate\Console\Command;

class BlacklistCommand extends Command
{
    protected $signature = 'botguardian:blacklist {ip : The IP address to blacklist}';

    protected $description = 'Add an IP to the BotGuardian blacklist (immediate permanent block)';

    public function handle(): int
    {
        $ip = trim($this->argument('ip'));

        if (! filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->error("Invalid IP address: {$ip}");
            return self::FAILURE;
        }

        $blacklist = config('botguardian.blacklist.ips', []);
        $enabled = config('botguardian.blacklist.enabled', false);

        if (in_array($ip, $blacklist, true)) {
            $this->warn("IP {$ip} is already in the blacklist.");
            return self::SUCCESS;
        }

        $blacklist[] = $ip;
        $this->updateConfig('botguardian.blacklist.ips', $blacklist);

        if (! $enabled) {
            $this->warn("Note: blacklist is currently disabled. Enable it in config/botguardian.php.");
        }

        $this->info("✓ IP {$ip} added to blacklist. (" . count($blacklist) . " total)");

        // Immediate block via BlockAction
        try {
            $blockAction = app(BlockAction::class);
            $blockAction->blockPermanent($ip);
            $this->info("✓ IP {$ip} has been permanently blocked immediately.");
        } catch (\Throwable $e) {
            $this->error("Failed to block IP: " . $e->getMessage());
            return self::FAILURE;
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
