<?php

namespace Febryntara\LaravelBotGuardian\Console\Commands;

use Febryntara\LaravelBotGuardian\Actions\BlockAction;
use Illuminate\Console\Command;

class UnblockCommand extends Command
{
    protected $signature = 'botguardian:unblock {ip : The IP address to unblock}';

    protected $description = 'Unblock an IP address from BotGuardian';

    public function handle(BlockAction $blockAction): int
    {
        $ip = trim($this->argument('ip'));

        if (! filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->error("Invalid IP address: {$ip}");
            return self::FAILURE;
        }

        if (! $blockAction->isBlocked($ip) && ! $blockAction->isPermanentBlocked($ip)) {
            $this->warn("IP {$ip} is not currently blocked.");
            return self::SUCCESS;
        }

        $blockAction->unblock($ip);
        $this->info("✓ IP {$ip} has been unblocked.");

        return self::SUCCESS;
    }
}
