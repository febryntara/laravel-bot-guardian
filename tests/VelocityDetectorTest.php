<?php

namespace Febryntara\LaravelBotGuardian\Tests;

use Febryntara\LaravelBotGuardian\Detectors\VelocityDetector;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class VelocityDetectorTest extends TestCase
{
    public function test_returns_zero_when_within_limit()
    {
        $config = config('botguardian.velocity');
        config(['botguardian.velocity.max_requests' => 5]);

        $detector = new VelocityDetector();
        $request = Request::create('/test');

        // Buat 4 request (masih di bawah limit 5)
        for ($i = 0; $i < 4; $i++) {
            $score = $detector->detect($request);
        }

        // Request ke-5 ini — masih di limit, harusnya 0
        $this->assertEquals(0, $score);
    }

    public function test_returns_score_when_exceeding_limit()
    {
        config(['botguardian.velocity.max_requests' => 3]);
        config(['botguardian.velocity.score' => 20]);

        $detector = new VelocityDetector();
        $request = Request::create('/test');

        // Buat 3 request untuk naikin counter
        $detector->detect($request);
        $detector->detect($request);
        $detector->detect($request);

        // Request ke-4 sudah exceed
        $score = $detector->detect($request);

        $this->assertEquals(20, $score);
    }

    public function test_returns_zero_when_disabled()
    {
        config(['botguardian.velocity.enabled' => false]);

        $detector = new VelocityDetector();
        $request = Request::create('/test');

        $this->assertEquals(0, $detector->detect($request));
    }

    public function test_different_ips_have_separate_counts()
    {
        config(['botguardian.velocity.max_requests' => 2]);

        $detector = new VelocityDetector();

        $requestA = Request::create('/test');
        $requestA->server->set('REMOTE_ADDR', '1.1.1.1');

        $requestB = Request::create('/test');
        $requestB->server->set('REMOTE_ADDR', '2.2.2.2');

        // IP A exceed limit
        $detector->detect($requestA);
        $detector->detect($requestA);

        // IP B masih fresh, harusnya 0
        $this->assertEquals(0, $detector->detect($requestB));

        // IP A sudah exceed, harusnya return score
        $this->assertGreaterThan(0, $detector->detect($requestA));
    }
}
