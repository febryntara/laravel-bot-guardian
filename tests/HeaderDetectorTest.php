<?php

namespace Febryntara\LaravelBotGuardian\Tests;

use Febryntara\LaravelBotGuardian\Detectors\HeaderDetector;
use Illuminate\Http\Request;

class HeaderDetectorTest extends TestCase
{
    public function test_detects_empty_user_agent()
    {
        config(['botguardian.headers.block_empty_user_agent' => true]);

        $detector = new HeaderDetector();

        $request = Request::create('/test');
        $request->headers->remove('User-Agent'); // Laravel 12 sets default, remove it

        $this->assertGreaterThan(0, $detector->detect($request));
    }

    public function test_detects_known_bot_user_agent()
    {
        $request = Request::create('/test');
        $request->headers->set('User-Agent', 'python-requests/2.28.0');

        $detector = new HeaderDetector();

        $this->assertGreaterThan(0, $detector->detect($request));
    }

    public function test_detects_missing_accept_language()
    {
        $detector = new HeaderDetector();

        $request = Request::create('/test');
        $request->headers->remove('Accept-Language'); // Laravel 12 sets default, remove it

        // Should return at least the missing Accept-Language score
        $this->assertGreaterThan(0, $detector->detect($request));
    }

    public function test_returns_zero_for_normal_browser()
    {
        $detector = new HeaderDetector();

        $request = Request::create('/test');
        $request->headers->set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0');
        $request->headers->set('Accept-Language', 'en-US,en;q=0.9');

        $this->assertEquals(0, $detector->detect($request));
    }

    public function test_returns_zero_when_disabled()
    {
        config(['botguardian.headers.enabled' => false]);

        $detector = new HeaderDetector();

        $request = Request::create('/test');

        $this->assertEquals(0, $detector->detect($request));
    }

    public function test_detects_curl_user_agent()
    {
        $request = Request::create('/test');
        $request->headers->set('User-Agent', 'curl/7.68.0');

        $detector = new HeaderDetector();

        $this->assertGreaterThan(0, $detector->detect($request));
    }
}
