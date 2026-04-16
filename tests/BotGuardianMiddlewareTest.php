<?php

namespace Febryntara\LaravelBotGuardian\Tests;

use Febryntara\LaravelBotGuardian\Middleware\BotGuardianMiddleware;
use Febryntara\LaravelBotGuardian\Scorer\BotScoreCalculator;
use Febryntara\LaravelBotGuardian\WhitelistChecker;
use Febryntara\LaravelBotGuardian\Actions\BlockAction;
use Febryntara\LaravelBotGuardian\RecidivistBlocker;
use Illuminate\Http\Request;
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
}
