<?php

namespace Febryntara\LaravelBotGuardian\Tests;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Orchestra\Testbench\TestCase;
use Febryntara\LaravelBotGuardian\Detectors\DistributedAttackDetector;

class DistributedAttackDetectorTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [\Febryntara\LaravelBotGuardian\BotGuardianServiceProvider::class];
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('botguardian.distributed.enabled', true);
        $app['config']->set('botguardian.distributed.window', 120);
        $app['config']->set('botguardian.distributed.ips_per_fingerprint', 3);
        $app['config']->set('botguardian.distributed.score_per_ip', 2);
        $app['config']->set('botguardian.distributed.max_fingerprint_score', 30);
        $app['config']->set('botguardian.distributed.endpoint_window', 300);
        $app['config']->set('botguardian.distributed.ips_per_endpoint', 5);
        $app['config']->set('botguardian.distributed.score_per_ip', 1);
        $app['config']->set('botguardian.distributed.max_endpoint_score', 30);
        $app['config']->set('botguardian.distributed.max_score', 60);
    }

    protected function setUp(): void
    {
        parent::setUp();
        Cache::flush();
    }

    public function test_disabled_returns_zero(): void
    {
        config(['botguardian.distributed.enabled' => false]);

        $detector = new DistributedAttackDetector();
        $request = Request::create('/login');

        $this->assertEquals(0, $detector->detect($request));
    }

    public function test_normal_user_under_threshold(): void
    {
        $detector = new DistributedAttackDetector();
        $request = Request::create('/login');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        // Under threshold → score = 0
        $this->assertEquals(0, $detector->detect($request));
    }

    public function test_fingerprint_cluster_excess_returns_score(): void
    {
        $detector = new DistributedAttackDetector();
        $ua = 'Mozilla/5.0 (scripted-bot)';
        $request = Request::create('/search');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');
        $request->headers->set('User-Agent', $ua);

        // Build the exact fingerprint the detector computes for this request.
        // Request::create() sets default Accept/Accept-Language headers, so we
        // must match exactly.
        $fingerprint = md5(implode('|', [
            $ua,
            $request->header('Accept', ''),
            $request->header('Accept-Language', ''),
            $request->header('Accept-Encoding', ''),
        ]));

        // Simulate 5 different IPs with identical UA (fingerprint cluster)
        for ($i = 1; $i <= 5; $i++) {
            Cache::put("botguardian:dist:fp:{$fingerprint}:ip:{$i}.0.0.1", true, 120);
            Cache::put("botguardian:dist:fp:{$fingerprint}", $i, 120);
        }

        // 6th IP from a different IP triggers excess score
        $score = $detector->detect($request);
        $this->assertGreaterThan(0, $score);
    }

    public function test_endpoint_concentration_on_login(): void
    {
        $detector = new DistributedAttackDetector();
        $request = Request::create('/login');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        // Simulate 6 IPs hitting /login (threshold is 5)
        $pathHash = md5('/login');
        for ($i = 1; $i <= 6; $i++) {
            Cache::put("botguardian:dist:ep:{$pathHash}:ip:{$i}.0.0.1", true, 300);
            Cache::put("botguardian:dist:ep:{$pathHash}", $i, 300);
        }

        $score = $detector->detect($request);
        $this->assertGreaterThan(0, $score);
    }

    public function test_non_sensitive_endpoint_no_concentration_score(): void
    {
        $detector = new DistributedAttackDetector();
        $request = Request::create('/about'); // not sensitive
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        // No concentration scoring for non-sensitive endpoints
        $this->assertEquals(0, $detector->detect($request));
    }

    public function test_max_score_capped(): void
    {
        $detector = new DistributedAttackDetector();
        $ua = 'extreme-bot-ua';

        // Build exact fingerprint (Request sets default Accept headers)
        $request = Request::create('/login');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');
        $request->headers->set('User-Agent', $ua);

        $fingerprint = md5(implode('|', [
            $ua,
            $request->header('Accept', ''),
            $request->header('Accept-Language', ''),
            $request->header('Accept-Encoding', ''),
        ]));

        // Simulate extreme cluster (100 IPs)
        for ($i = 1; $i <= 100; $i++) {
            Cache::put("botguardian:dist:fp:{$fingerprint}:ip:{$i}.0.0.1", true, 120);
        }
        Cache::put("botguardian:dist:fp:{$fingerprint}", 100, 120);

        $score = $detector->detect($request);
        $this->assertLessThanOrEqual(60, $score);
    }
}
