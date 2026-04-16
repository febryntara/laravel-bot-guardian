<?php

namespace Febryntara\LaravelBotGuardian\Tests;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Orchestra\Testbench\TestCase;
use Febryntara\LaravelBotGuardian\Detectors\SlowAttackDetector;

class SlowAttackDetectorTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [\Febryntara\LaravelBotGuardian\BotGuardianServiceProvider::class];
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('botguardian.slow_attack.enabled', true);
        $app['config']->set('botguardian.slow_attack.long_window', 86400);
        $app['config']->set('botguardian.slow_attack.daily_request_limit', 100);
        $app['config']->set('botguardian.slow_attack.long_window_score', 20);
        $app['config']->set('botguardian.slow_attack.interval_window', 600);
        $app['config']->set('botguardian.slow_attack.interval_coef_threshold', 0.1);
        $app['config']->set('botguardian.slow_attack.regular_interval_score', 25);
        $app['config']->set('botguardian.slow_attack.diversity_window', 3600);
        $app['config']->set('botguardian.slow_attack.min_requests_for_diversity', 5);
        $app['config']->set('botguardian.slow_attack.min_unique_endpoints', 3);
        $app['config']->set('botguardian.slow_attack.low_diversity_score', 30);
        $app['config']->set('botguardian.slow_attack.max_score', 60);
    }

    protected function setUp(): void
    {
        parent::setUp();
        Cache::flush();
    }

    public function test_disabled_returns_zero(): void
    {
        config(['botguardian.slow_attack.enabled' => false]);

        $detector = new SlowAttackDetector();
        $request = Request::create('/');

        $this->assertEquals(0, $detector->detect($request));
    }

    public function test_first_requests_no_score(): void
    {
        $detector = new SlowAttackDetector();
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        $score = $detector->detect($request);
        $this->assertEquals(0, $score);
    }

    public function test_long_window_excess_returns_score(): void
    {
        $detector = new SlowAttackDetector();
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        // Simulate 150 requests (over limit of 100)
        $key = "botguardian:slow:long:127.0.0.1";
        Cache::put($key, 150, 86400);

        $score = $detector->detect($request);
        $this->assertGreaterThan(0, $score);
    }

    public function test_regular_interval_returns_score(): void
    {
        $detector = new SlowAttackDetector();
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        // Build 10 evenly-spaced intervals ending exactly 1 interval before "now".
        // Detector adds $now → diffs = [60×10] → stddev=0 → relStddev=0.
        //
        // Formula: start = now - interval, then go backward.
        // Pre-stored: [now-60, now-120, ..., now-600] = 10 entries.
        // Detector adds now → [now-60, ..., now-600, now] = 11 entries, 10 diffs all 60.
        $now = microtime(true);
        $interval = 60.0;
        $count = 10;
        $intervals = [];
        for ($i = 1; $i <= $count; $i++) {
            $intervals[] = $now - $interval * $i;
        }
        // Last pre-stored = now - interval (60s before now)

        $rc = new \ReflectionClass($detector);
        $method = $rc->getMethod('checkSlowInterval');
        $method->setAccessible(true);

        $cfg = config('botguardian.slow_attack');
        $score = $method->invoke($detector, '127.0.0.1', $cfg, $intervals);
        $this->assertEquals(25, $score);
    }

    public function test_random_intervals_no_score(): void
    {
        $detector = new SlowAttackDetector();
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        // Build random intervals (high variance → relStddev > 0.1)
        $base = microtime(true);
        $intervals = [$base - 300, $base - 280, $base - 200, $base - 150, $base - 50];

        $rc = new \ReflectionClass($detector);
        $method = $rc->getMethod('checkSlowInterval');
        $method->setAccessible(true);

        $cfg = config('botguardian.slow_attack');
        $score = $method->invoke($detector, '127.0.0.1', $cfg, $intervals);
        $this->assertEquals(0, $score);
    }

    public function test_low_endpoint_diversity_returns_score(): void
    {
        $detector = new SlowAttackDetector();
        $request = Request::create('/login');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        // Simulate 20 requests but only to 2 unique endpoints
        Cache::put("botguardian:slow:count:127.0.0.1", 20, 3600);
        Cache::put("botguardian:slow:endpoints:127.0.0.1", ['/login', '/login'], 3600);

        $score = $detector->detect($request);
        $this->assertEquals(30, $score);
    }

    public function test_high_endpoint_diversity_returns_zero(): void
    {
        $detector = new SlowAttackDetector();
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        // Simulate diverse endpoints
        Cache::put("botguardian:slow:count:127.0.0.1", 20, 3600);
        Cache::put("botguardian:slow:endpoints:127.0.0.1", [
            '/', '/home', '/products', '/about', '/contact',
        ], 3600);

        $score = $detector->detect($request);
        $this->assertEquals(0, $score);
    }

    public function test_max_score_capped(): void
    {
        $detector = new SlowAttackDetector();
        $request = Request::create('/login');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        // Trigger all 3 checks simultaneously
        Cache::put("botguardian:slow:long:127.0.0.1", 500, 86400);
        Cache::put("botguardian:slow:count:127.0.0.1", 20, 3600);
        Cache::put("botguardian:slow:endpoints:127.0.0.1", ['/login', '/login'], 3600);

        $now = microtime(true);
        $intervals = [];
        for ($i = 0; $i < 10; $i++) {
            $intervals[] = $now - (9 - $i) * 60;
        }
        Cache::put("botguardian:slow:intervals:127.0.0.1", $intervals, 600);

        $score = $detector->detect($request);
        $this->assertLessThanOrEqual(60, $score);
    }
}
