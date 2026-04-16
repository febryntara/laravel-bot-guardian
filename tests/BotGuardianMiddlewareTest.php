<?php

namespace Febryntara\LaravelBotGuardian\Tests;

use Febryntara\LaravelBotGuardian\Middleware\BotGuardianMiddleware;
use Febryntara\LaravelBotGuardian\Scorer\BotScoreCalculator;
use Febryntara\LaravelBotGuardian\WhitelistChecker;
use Febryntara\LaravelBotGuardian\Actions\BlockAction;
use Febryntara\LaravelBotGuardian\RecidivistBlocker;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Cache;

class BotGuardianMiddlewareTest extends TestCase
{
    protected BotGuardianMiddleware $middleware;

    protected function setUp(): void
    {
        parent::setUp();
        config(['botguardian.enabled' => true]);
        config(['botguardian.whitelist.enabled' => false]);
        config(['botguardian.blacklist.enabled' => false]);
        config(['botguardian.recidivist.enabled' => false]);
        config(['botguardian.threshold' => 50]);
        config(['botguardian.honeypot.score' => 50]);

        $this->middleware = new BotGuardianMiddleware(
            new BotScoreCalculator(),
            new WhitelistChecker(),
            new BlockAction(new RecidivistBlocker()),
            new RecidivistBlocker()
        );
    }

    public function test_blocks_ip_when_honeypot_threshold_reached()
    {
        $ip = '10.0.0.1';
        $request = Request::create('/wp-login.php');
        $request->headers->set('User-Agent', 'Mozilla/5.0');
        $request->headers->set('Accept-Language', 'en-US');
        $request->server->set('REMOTE_ADDR', $ip);
        $request->setRouteResolver(fn () => new \stdClass());

        $response = $this->middleware->handle($request, fn($req) => 'should_not_pass');
        $this->assertNotEquals('should_not_pass', $response);
        $this->assertEquals(403, $response->getStatusCode());
        $this->assertTrue(Cache::has("botguardian:blocked:{$ip}"));
    }

    public function test_passes_normal_request_through()
    {
        config(['botguardian.threshold' => 9999]);
        $request = Request::create('/normal-page');
        $request->headers->set('User-Agent', 'Mozilla/5.0');
        $request->headers->set('Accept-Language', 'en-US');

        $result = $this->middleware->handle($request, fn($req) => 'ok');
        $this->assertEquals('ok', $result);
    }

    public function test_does_nothing_when_disabled()
    {
        config(['botguardian.enabled' => false]);
        $request = Request::create('/wp-login.php');
        $request->server->set('REMOTE_ADDR', '10.0.0.5');

        $response = $this->middleware->handle($request, fn($req) => 'passthrough');
        $this->assertEquals('passthrough', $response);
    }

    public function test_whitelisted_ip_bypasses()
    {
        config(['botguardian.whitelist.enabled' => true]);
        config(['botguardian.whitelist.ips' => ['10.0.0.99']]);

        $request = Request::create('/wp-login.php');
        $request->server->set('REMOTE_ADDR', '10.0.0.99');

        $result = $this->middleware->handle($request, fn($req) => 'ok');
        $this->assertEquals('ok', $result);
    }

    public function test_blacklisted_ip_immediate_block()
    {
        config(['botguardian.blacklist.enabled' => true]);
        config(['botguardian.blacklist.ips' => ['10.0.0.88']]);

        $request = Request::create('/normal-page');
        $request->server->set('REMOTE_ADDR', '10.0.0.88');

        $response = $this->middleware->handle($request, fn($req) => 'ok');
        $this->assertEquals(403, $response->getStatusCode());
    }

    public function test_terminate_adds_score_for_404_response()
    {
        config(['botguardian.threshold' => 30]);
        config(['botguardian.not_found_spam.max_hits' => 10]);
        config(['botguardian.not_found_spam.score' => 30]);
        $ip = '10.0.0.200';

        // NOTE: terminate() fires AFTER handle() returns a response.
        // The block activates on the NEXT handle() call, not the current one.
        // So we need: 10 passes → 1 pass that triggers scoring in terminate() →
        // NEXT request gets blocked.

        // First 10 requests: 404 count=10, score not yet added (no threshold hit)
        for ($i = 0; $i < 10; $i++) {
            $request = Request::create('/nonexistent-' . $i);
            $request->server->set('REMOTE_ADDR', $ip);
            $response = new Response('Not Found', 404);
            $result = $this->middleware->handle($request, fn($req) => $response);
            $this->assertEquals(404, $result->getStatusCode()); // not blocked yet
            $this->middleware->terminate($request, $response);
        }

        // 11th request: count becomes 11 > 10, 404 score=30 added in terminate()
        // But block activates AFTER response, so this request passes through
        $request = Request::create('/nonexistent-10');
        $request->server->set('REMOTE_ADDR', $ip);
        $response = new Response('Not Found', 404);
        $result = $this->middleware->handle($request, fn($req) => $response);
        $this->assertEquals(404, $result->getStatusCode()); // passes through (block after response)
        $this->middleware->terminate($request, $response);

        // 12th request: IP is now blocked → 403
        $request = Request::create('/anything');
        $request->server->set('REMOTE_ADDR', $ip);
        $result = $this->middleware->handle($request, fn($req) => new Response('OK'));
        $this->assertEquals(403, $result->getStatusCode());
        $this->assertTrue(Cache::has("botguardian:blocked:{$ip}"));
    }
}
