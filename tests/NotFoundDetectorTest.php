<?php

namespace Febryntara\LaravelBotGuardian\Tests;

use Febryntara\LaravelBotGuardian\Detectors\NotFoundDetector;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class NotFoundDetectorTest extends TestCase
{
    public function test_detects_no_route_match()
    {
        config(['botguardian.not_found_spam.max_hits' => 2]);
        config(['botguardian.not_found_spam.score' => 30]);

        $detector = new NotFoundDetector();
        $request = Request::create('/non-existent-path');

        // Simulate no route resolved
        $request->setRouteResolver(fn () => null);

        $detector->detect($request);
        $detector->detect($request);

        $score = $detector->detect($request);

        $this->assertEquals(30, $score);
    }

    public function test_returns_zero_when_route_exists()
    {
        $detector = new NotFoundDetector();
        $request = Request::create('/dashboard');

        // Simulate route resolved
        $request->setRouteResolver(fn () => new \stdClass());

        $this->assertEquals(0, $detector->detect($request));
    }

    public function test_returns_zero_when_disabled()
    {
        config(['botguardian.not_found_spam.enabled' => false]);

        $detector = new NotFoundDetector();
        $request = Request::create('/non-existent');
        $request->setRouteResolver(fn () => null);

        $this->assertEquals(0, $detector->detect($request));
    }
}
