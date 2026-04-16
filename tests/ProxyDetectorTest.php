<?php

namespace Febryntara\LaravelBotGuardian\Tests;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Orchestra\Testbench\TestCase;
use Febryntara\LaravelBotGuardian\Detectors\ProxyDetector;

class ProxyDetectorTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [\Febryntara\LaravelBotGuardian\BotGuardianServiceProvider::class];
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('botguardian.proxy.enabled', true);
        $app['config']->set('botguardian.proxy.max_xff_hops', 3);
        $app['config']->set('botguardian.proxy.xff_too_many_hops_score', 20);
        $app['config']->set('botguardian.proxy.xff_private_ip_score', 30);
        $app['config']->set('botguardian.proxy.xff_without_xri_score', 10);
        $app['config']->set('botguardian.proxy.xff_spoofed_chain_score', 35);
        $app['config']->set('botguardian.proxy.xff_matches_direct_ip_score', 25);
        $app['config']->set('botguardian.proxy.via_header_score', 25);
        $app['config']->set('botguardian.proxy.xri_alone_score', 15);
        $app['config']->set('botguardian.proxy.xri_private_ip_score', 30);
        $app['config']->set('botguardian.proxy.forwarded_private_score', 30);
        $app['config']->set('botguardian.proxy.max_score', 50);
    }

    protected function setUp(): void
    {
        parent::setUp();
        Cache::flush();
    }

    public function test_disabled_returns_zero(): void
    {
        config(['botguardian.proxy.enabled' => false]);

        $detector = new ProxyDetector();
        $request = Request::create('/');

        $this->assertEquals(0, $detector->detect($request));
    }

    public function test_clean_request_returns_zero(): void
    {
        $detector = new ProxyDetector();
        $request = Request::create('/');

        $this->assertEquals(0, $detector->detect($request));
    }

    public function test_via_header_returns_score(): void
    {
        $detector = new ProxyDetector();
        $request = Request::create('/');
        $request->headers->set('Via', '1.1 proxy.example.com');

        $this->assertEquals(25, $detector->detect($request));
    }

    public function test_xff_with_private_ip_returns_score(): void
    {
        $detector = new ProxyDetector();
        $request = Request::create('/');
        $request->headers->set('X-Forwarded-For', '203.0.113.50, 10.0.0.5');

        $score = $detector->detect($request);
        $this->assertGreaterThan(0, $score);
    }

    public function test_xff_spoofed_chain_with_private_rightmost(): void
    {
        $detector = new ProxyDetector();
        $request = Request::create('/');
        $request->headers->set('X-Forwarded-For', '203.0.113.50, 192.168.1.100');

        $score = $detector->detect($request);
        $this->assertGreaterThan(0, $score);
    }

    public function test_xff_chain_too_long(): void
    {
        $detector = new ProxyDetector();
        $request = Request::create('/');
        $request->headers->set('X-Forwarded-For', '203.0.113.1, 10.0.0.2, 172.16.0.3, 192.168.1.4');

        $score = $detector->detect($request);
        $this->assertGreaterThan(0, $score);
    }

    public function test_xff_matches_direct_ip(): void
    {
        $detector = new ProxyDetector();
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '203.0.113.50');
        $request->headers->set('X-Forwarded-For', '10.0.0.5, 203.0.113.50');

        $score = $detector->detect($request);
        $this->assertGreaterThan(0, $score);
    }

    public function test_xri_alone_without_xff(): void
    {
        $detector = new ProxyDetector();
        $request = Request::create('/');
        $request->headers->set('X-Real-IP', '203.0.113.50');

        $score = $detector->detect($request);
        $this->assertEquals(15, $score);
    }

    public function test_forwarded_header_with_private_ip(): void
    {
        $detector = new ProxyDetector();
        $request = Request::create('/');
        $request->headers->set('Forwarded', 'for=192.168.1.100;host=example.com');

        $score = $detector->detect($request);
        $this->assertEquals(30, $score);
    }

    public function test_max_score_capped(): void
    {
        $detector = new ProxyDetector();
        $request = Request::create('/');
        // Send multiple signals at once
        $request->headers->set('Via', '1.1 proxy');
        $request->headers->set('X-Forwarded-For', '203.0.113.1, 10.0.0.2, 172.16.0.3, 192.168.1.4, 127.0.0.1');
        $request->headers->set('X-Real-IP', '192.168.1.50');
        $request->headers->set('Forwarded', 'for=192.168.1.100');

        $score = $detector->detect($request);
        $this->assertLessThanOrEqual(50, $score);
    }
}
