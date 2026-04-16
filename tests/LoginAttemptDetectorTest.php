<?php

namespace Febryntara\LaravelBotGuardian\Tests;

use Febryntara\LaravelBotGuardian\Detectors\LoginAttemptDetector;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class LoginAttemptDetectorTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        config(['botguardian.login_attempts.enabled' => true]);
        config(['botguardian.login_attempts.max_attempts' => 5]);
        config(['botguardian.login_attempts.time_window' => 300]);
        config(['botguardian.login_attempts.score' => 40]);
        config(['botguardian.login_attempts.routes' => ['login', 'auth/login', 'api/login']]);
    }

    public function test_returns_zero_for_non_auth_routes()
    {
        $detector = new LoginAttemptDetector();
        $request = Request::create('/dashboard');
        $request->server->set('REMOTE_ADDR', '10.0.0.1');
        $this->assertEquals(0, $detector->detect($request));
    }

    public function test_returns_zero_for_get_request()
    {
        $detector = new LoginAttemptDetector();
        $request = Request::create('/login', 'GET');
        $request->server->set('REMOTE_ADDR', '10.0.0.1');
        $this->assertEquals(0, $detector->detect($request));
    }

    public function test_returns_score_when_exceeding_max_attempts()
    {
        $detector = new LoginAttemptDetector();
        $ip = '10.0.0.99';
        Cache::forget("botguardian:login_attempts:{$ip}");

        // Simulate 6 failed attempts — DON'T clear inside loop
        for ($i = 0; $i < 6; $i++) {
            $request = Request::create('/login', 'POST');
            $request->server->set('REMOTE_ADDR', $ip);
            $detector->detect($request);
        }

        // 6th request should trigger
        $request = Request::create('/login', 'POST');
        $request->server->set('REMOTE_ADDR', $ip);
        $this->assertEquals(40, $detector->detect($request));

        // Cleanup
        Cache::forget("botguardian:login_attempts:{$ip}");
    }

    public function test_returns_zero_when_disabled()
    {
        config(['botguardian.login_attempts.enabled' => false]);
        $detector = new LoginAttemptDetector();
        $request = Request::create('/login', 'POST');
        $request->server->set('REMOTE_ADDR', '10.0.0.1');
        $this->assertEquals(0, $detector->detect($request));
    }
}
