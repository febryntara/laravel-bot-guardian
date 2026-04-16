<?php

namespace Febryntara\LaravelBotGuardian\Tests;

use Febryntara\LaravelBotGuardian\WhitelistChecker;
use Illuminate\Support\Facades\Cache;

class WhitelistCheckerTest extends TestCase
{
    protected WhitelistChecker $checker;

    protected function setUp(): void
    {
        parent::setUp();
        $this->checker = new WhitelistChecker();
        config(['botguardian.whitelist.enabled' => true]);
        config(['botguardian.blacklist.enabled' => true]);
        // Clear dynamic lists
        Cache::forget('botguardian:whitelist');
        Cache::forget('botguardian:blacklist');
    }

    public function test_whitelisted_ip_bypasses_detection()
    {
        config(['botguardian.whitelist.ips' => ['127.0.0.1']]);
        $this->assertTrue($this->checker->isWhitelisted('127.0.0.1'));
        $this->assertFalse($this->checker->isWhitelisted('192.168.1.1'));
    }

    public function test_blacklisted_ip_is_blocked()
    {
        config(['botguardian.blacklist.ips' => ['1.2.3.4']]);
        $this->assertTrue($this->checker->isBlacklisted('1.2.3.4'));
        $this->assertFalse($this->checker->isBlacklisted('5.6.7.8'));
    }

    public function test_cidr_notation_matches()
    {
        config(['botguardian.whitelist.ips' => ['10.0.0.0/24']]);
        $this->assertTrue($this->checker->isWhitelisted('10.0.0.1'));
        $this->assertTrue($this->checker->isWhitelisted('10.0.0.255'));
        $this->assertFalse($this->checker->isWhitelisted('10.0.1.1'));
    }

    public function test_wildcard_matches()
    {
        config(['botguardian.whitelist.ips' => ['192.168.*']]);
        $this->assertTrue($this->checker->isWhitelisted('192.168.1.1'));
        $this->assertTrue($this->checker->isWhitelisted('192.168.99.99'));
        $this->assertFalse($this->checker->isWhitelisted('192.169.1.1'));
    }

    public function test_dynamic_whitelist_runtime()
    {
        // Use unique IP to avoid cross-test pollution
        $testIp = '10.99.99.99';
        $this->assertFalse($this->checker->isWhitelisted($testIp));

        $this->checker->whitelist($testIp);
        $this->assertTrue($this->checker->isWhitelisted($testIp));

        $this->checker->unwhitelist($testIp);
        $this->assertFalse($this->checker->isWhitelisted($testIp));
    }

    public function test_dynamic_blacklist_runtime()
    {
        $testIp = '10.88.88.88';
        $this->assertFalse($this->checker->isBlacklisted($testIp));

        $this->checker->blacklist($testIp);
        $this->assertTrue($this->checker->isBlacklisted($testIp));

        $this->checker->unblacklist($testIp);
        $this->assertFalse($this->checker->isBlacklisted($testIp));
    }
}
