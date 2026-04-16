<?php

namespace Febryntara\LaravelBotGuardian\Tests;

use Febryntara\LaravelBotGuardian\Detectors\BehavioralPatternDetector;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class BehavioralPatternDetectorTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        config(['botguardian.behavioral.enabled' => true]);
        config(['botguardian.behavioral.window' => 120]);
        config(['botguardian.behavioral.check_no_asset' => true]);
        config(['botguardian.behavioral.check_regular_interval' => true]);
        config(['botguardian.behavioral.check_header_fingerprint' => true]);
        config(['botguardian.behavioral.check_deep_links' => true]);
        config(['botguardian.behavioral.no_asset_min_requests' => 10]);
        config(['botguardian.behavioral.no_asset_ratio_threshold' => 0.1]);
        config(['botguardian.behavioral.no_asset_score' => 25]);
        config(['botguardian.behavioral.interval_stddev_threshold' => 0.05]);
        config(['botguardian.behavioral.regular_interval_score' => 30]);
        config(['botguardian.behavioral.missing_sec_fetch_score' => 15]);
        config(['botguardian.behavioral.deep_link_score' => 20]);
        config(['botguardian.behavioral.min_deep_links' => 5]);
    }

    public function test_returns_zero_for_disabled()
    {
        config(['botguardian.behavioral.enabled' => false]);
        $detector = new BehavioralPatternDetector();
        $request = Request::create('/api/data');
        $request->server->set('REMOTE_ADDR', '10.0.0.1');
        $this->assertEquals(0, $detector->detect($request));
    }

    public function test_returns_score_for_headless_browser()
    {
        $detector = new BehavioralPatternDetector();
        $request = Request::create('/api/data');
        $request->server->set('REMOTE_ADDR', '10.0.0.1');
        $request->headers->set('User-Agent', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
        $request->headers->set('Accept', 'application/json');

        $score = $detector->detect($request);
        $this->assertGreaterThan(0, $score);
    }

    public function test_returns_low_score_for_normal_browser()
    {
        $detector = new BehavioralPatternDetector();
        $request = Request::create('/page');
        $request->server->set('REMOTE_ADDR', '10.0.0.1');
        $request->headers->set('User-Agent', 'Mozilla/5.0');
        $request->headers->set('Accept', 'text/html');
        $request->headers->set('Accept-Language', 'en-US');
        $request->headers->set('Sec-Fetch-Site', 'same-origin');
        $request->headers->set('Sec-Fetch-Mode', 'navigate');
        $request->headers->set('Sec-Fetch-Dest', 'document');
        $request->headers->set('Referer', 'https://example.com/previous');

        $score = $detector->detect($request);
        $this->assertLessThan(20, $score);
    }

    public function test_deep_link_detection()
    {
        $detector = new BehavioralPatternDetector();
        $ip = '10.0.0.200';

        // DON'T clear inside loop — score needs to accumulate
        for ($i = 0; $i < 6; $i++) {
            $request = Request::create('/product/' . $i);
            $request->server->set('REMOTE_ADDR', $ip);
            $detector->detect($request);
        }

        $request2 = Request::create('/product/7');
        $request2->server->set('REMOTE_ADDR', $ip);
        $score = $detector->detect($request2);
        $this->assertGreaterThan(0, $score);

        // Cleanup
        Cache::forget("botguardian:behavior:{$ip}:deeplinks");
    }
}
