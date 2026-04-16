<?php

namespace Febryntara\LaravelBotGuardian;

use Febryntara\LaravelBotGuardian\Middleware\BotGuardianMiddleware;
use Febryntara\LaravelBotGuardian\Scorer\BotScoreCalculator;
use Febryntara\LaravelBotGuardian\WhitelistChecker;
use Febryntara\LaravelBotGuardian\Actions\BlockAction;
use Febryntara\LaravelBotGuardian\Actions\LogAction;
use Illuminate\Support\ServiceProvider;

class BotGuardianServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/../config/botguardian.php' => config_path('botguardian.php'),
        ], 'botguardian-config');

        $this->loadViewsFrom(__DIR__ . '/resources/views', 'botguardian');

        $router = $this->app['router'];

        if (method_exists($router, 'aliasMiddleware')) {
            $router->aliasMiddleware('botguardian', BotGuardianMiddleware::class);
        } else {
            $router->middleware('botguardian', BotGuardianMiddleware::class);
        }
    }

    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/botguardian.php',
            'botguardian'
        );

        // Singleton: only one instance per app lifecycle
        $this->app->singleton(BotScoreCalculator::class);
        $this->app->singleton(WhitelistChecker::class);
        $this->app->singleton(RecidivistBlocker::class);
        $this->app->singleton(BlockAction::class);
        $this->app->singleton(LogAction::class);
    }
}
