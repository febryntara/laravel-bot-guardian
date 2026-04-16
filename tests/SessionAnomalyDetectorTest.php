<?php

namespace Febryntara\LaravelBotGuardian\Tests;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Session;
use Orchestra\Testbench\TestCase;
use Febryntara\LaravelBotGuardian\Detectors\SessionAnomalyDetector;

class SessionAnomalyDetectorTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [\Febryntara\LaravelBotGuardian\BotGuardianServiceProvider::class];
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('botguardian.session.enabled', true);
        $app['config']->set('botguardian.session.max_ips_per_session', 3);
        $app['config']->set('botguardian.session.session_fixation_score', 40);
        $app['config']->set('botguardian.session.session_hijack_score', 30);
        $app['config']->set('botguardian.session.burst_window', 60);
        $app['config']->set('botguardian.session.max_burst_requests', 10);
        $app['config']->set('botguardian.session.burst_score', 20);
        $app['config']->set('botguardian.session.session_tracking_window', 86400);
        $app['config']->set('botguardian.session.max_score', 50);
    }

    protected function setUp(): void
    {
        parent::setUp();
        Cache::flush();
        Session::flush();
    }

    public function test_disabled_returns_zero(): void
    {
        config(['botguardian.session.enabled' => false]);

        $detector = new SessionAnomalyDetector();
        $request = Request::create('/');
        $request->setLaravelSession($this->app['session.store']);

        $this->assertEquals(0, $detector->detect($request));
    }

    public function test_first_visit_no_score(): void
    {
        $detector = new SessionAnomalyDetector();
        $request = Request::create('/');
        $request->setLaravelSession($this->app['session.store']);

        $score = $detector->detect($request);
        $this->assertEquals(0, $score);
    }

    public function test_same_ip_same_session_no_score(): void
    {
        $detector = new SessionAnomalyDetector();
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');
        $request->setLaravelSession($this->app['session.store']);
        $sessionId = $request->session()->getId();

        // First request
        $detector->detect($request);

        // Same session, same IP → no score
        $request2 = Request::create('/');
        $request2->server->set('REMOTE_ADDR', '127.0.0.1');
        $request2->setLaravelSession($this->app['session.store']);

        $score = $detector->detect($request2);
        $this->assertEquals(0, $score);
    }

    public function test_session_hijack_returns_score(): void
    {
        $detector = new SessionAnomalyDetector();
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');
        $request->setLaravelSession($this->app['session.store']);
        $sessionId = $request->session()->getId();

        // Simulate 4 different IPs using the same session (hijacking)
        $key = "botguardian:session:hijack:{$sessionId}";
        for ($i = 1; $i <= 4; $i++) {
            $ip = "{$i}.0.0.1";
            Cache::put("botguardian:session:hijack:{$sessionId}:ip:{$ip}", true, 86400);
        }
        Cache::put($key, 4, 86400);

        $score = $detector->detect($request);
        $this->assertEquals(30, $score);
    }

    public function test_session_burst_returns_score(): void
    {
        $detector = new SessionAnomalyDetector();
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');
        $request->setLaravelSession($this->app['session.store']);
        $sessionId = $request->session()->getId();

        // Simulate burst: 15 requests in 60s
        Cache::put("botguardian:session:burst:{$sessionId}", 15, 60);

        $score = $detector->detect($request);
        $this->assertEquals(20, $score);
    }

    public function test_max_score_capped(): void
    {
        $detector = new SessionAnomalyDetector();
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');
        $request->setLaravelSession($this->app['session.store']);
        $sessionId = $request->session()->getId();

        // Trigger both hijack and burst
        $key = "botguardian:session:hijack:{$sessionId}";
        for ($i = 1; $i <= 5; $i++) {
            $ip = "{$i}.0.0.1";
            Cache::put("botguardian:session:hijack:{$sessionId}:ip:{$ip}", true, 86400);
        }
        Cache::put($key, 5, 86400);
        Cache::put("botguardian:session:burst:{$sessionId}", 15, 60);

        $score = $detector->detect($request);
        $this->assertLessThanOrEqual(50, $score);
    }
}
