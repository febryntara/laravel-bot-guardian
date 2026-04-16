<?php

namespace Febryntara\LaravelBotGuardian\Tests;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Orchestra\Testbench\TestCase;
use Febryntara\LaravelBotGuardian\Detectors\JsChallengeDetector;

class JsChallengeDetectorTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [\Febryntara\LaravelBotGuardian\BotGuardianServiceProvider::class];
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('botguardian.js_challenge.enabled', true);
        $app['config']->set('botguardian.js_challenge.secret', 'test-secret-key');
        $app['config']->set('botguardian.js_challenge.token_validity', 300);
        $app['config']->set('botguardian.js_challenge.missing_token_score', 35);
        $app['config']->set('botguardian.js_challenge.invalid_token_score', 50);
        $app['config']->set('botguardian.js_challenge.skip_prefixes', ['api/', '_debugbar/']);
    }

    protected function setUp(): void
    {
        parent::setUp();
        Cache::flush();
    }

    public function test_enabled_returns_zero(): void
    {
        config(['botguardian.js_challenge.enabled' => false]);

        $detector = new JsChallengeDetector();
        $request = Request::create('/home', 'GET');

        $this->assertEquals(0, $detector->detect($request));
    }

    public function test_missing_token_returns_score(): void
    {
        $detector = new JsChallengeDetector();
        $request = Request::create('/home', 'GET', [], []); // no cookies

        $score = $detector->detect($request);
        $this->assertEquals(35, $score);
    }

    public function test_invalid_token_returns_score(): void
    {
        $detector = new JsChallengeDetector();
        $request = Request::create('/home', 'GET', [], ['bg_chk' => 'fake-token']);

        $score = $detector->detect($request);
        $this->assertEquals(50, $score);
    }

    public function test_valid_token_returns_zero(): void
    {
        $detector = new JsChallengeDetector();
        $token = $detector->generateToken('127.0.0.1');
        $request = Request::create('/home', 'GET', [], ['bg_chk' => $token]);

        $score = $detector->detect($request);
        $this->assertEquals(0, $score);
    }

    public function test_token_tied_to_ip(): void
    {
        $detector = new JsChallengeDetector();
        $tokenForIpA = $detector->generateToken('192.168.1.1');
        $tokenForIpB = $detector->generateToken('10.0.0.1');

        // Token for IP A should NOT validate for IP B
        $request = Request::create('/home', 'GET', [], ['bg_chk' => $tokenForIpA]);
        $request->server->set('REMOTE_ADDR', '10.0.0.1'); // Different IP

        $score = $detector->detect($request);
        $this->assertEquals(50, $score);

        // Token for IP B should validate for IP B
        $request2 = Request::create('/home', 'GET', [], ['bg_chk' => $tokenForIpB]);
        $request2->server->set('REMOTE_ADDR', '10.0.0.1');

        $this->assertEquals(0, $detector->detect($request2));
    }

    public function test_api_routes_skipped(): void
    {
        $detector = new JsChallengeDetector();
        $request = Request::create('/api/users', 'GET');

        $score = $detector->detect($request);
        $this->assertEquals(0, $score);
    }

    public function test_debugbar_routes_skipped(): void
    {
        $detector = new JsChallengeDetector();
        $request = Request::create('/_debugbar/assets', 'GET');

        $score = $detector->detect($request);
        $this->assertEquals(0, $score);
    }
}
