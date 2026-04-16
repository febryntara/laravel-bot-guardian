<?php

namespace Febryntara\LaravelBotGuardian\Tests;

use Febryntara\LaravelBotGuardian\Detectors\HoneypotDetector;
use Illuminate\Http\Request;

class HoneypotDetectorTest extends TestCase
{
    public function test_detects_honeypot_route()
    {
        config(['botguardian.honeypot.enabled' => true]);

        $detector = new HoneypotDetector();

        $request = Request::create('/wp-login.php');

        $this->assertGreaterThan(0, $detector->detect($request));
    }

    public function test_detects_nested_honeypot_route()
    {
        $detector = new HoneypotDetector();

        $request = Request::create('/wp-admin/some-page');

        $this->assertGreaterThan(0, $detector->detect($request));
    }

    public function test_returns_zero_for_normal_route()
    {
        $detector = new HoneypotDetector();

        $request = Request::create('/dashboard');

        $this->assertEquals(0, $detector->detect($request));
    }

    public function test_returns_zero_when_disabled()
    {
        config(['botguardian.honeypot.enabled' => false]);

        $detector = new HoneypotDetector();

        $request = Request::create('/wp-login.php');

        $this->assertEquals(0, $detector->detect($request));
    }

    public function test_returns_configured_score()
    {
        config(['botguardian.honeypot.score' => 50]);

        $detector = new HoneypotDetector();

        $request = Request::create('/.env');

        $this->assertEquals(50, $detector->detect($request));
    }
}
