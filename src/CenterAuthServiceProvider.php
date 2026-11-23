<?php

namespace CenterAuth;

use CenterAuth\Client\ClientAuthService;
use CenterAuth\Client\Http\Middleware\AuthenticateWithCenterAuth;
use CenterAuth\Client\UserSynchronizer;
use CenterAuth\Console\GenerateKeysCommand;
use CenterAuth\Contracts\ClientRepository;
use CenterAuth\Server\Repositories\ConfigClientRepository;
use CenterAuth\Server\Repositories\DatabaseClientRepository;
use CenterAuth\Server\ServerAuthService;
use CenterAuth\Support\KeyLoader;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;

class CenterAuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/center-auth.php', 'center-auth');

        $this->app->singleton(KeyLoader::class);
        $this->app->singleton(UserSynchronizer::class);
        $this->app->singleton(CenterAuthManager::class, fn ($app) => new CenterAuthManager($app));

        $this->app->bind(ClientRepository::class, function ($app): ClientRepository {
            $driver = strtolower((string) config('center-auth.server.client_driver', 'config'));

            return $driver === 'database'
                ? $app->make(DatabaseClientRepository::class)
                : $app->make(ConfigClientRepository::class);
        });

        $this->app->bind(ServerAuthService::class, fn ($app) => new ServerAuthService(
            $app->make(KeyLoader::class),
            $app->make(CenterAuthManager::class),
            $app->make(ClientRepository::class),
        ));

        $this->app->singleton(ClientAuthService::class, fn ($app) => new ClientAuthService(
            $app->make(KeyLoader::class),
            $app->make(UserSynchronizer::class),
            $app->make(CenterAuthManager::class),
        ));
    }

    public function boot(): void
    {
        $this->loadViewsFrom(__DIR__ . '/../resources/views', 'center-auth');

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/center-auth.php' => config_path('center-auth.php'),
            ], 'center-auth-config');

            $this->publishes([
                __DIR__ . '/../database/migrations' => database_path('migrations'),
            ], 'center-auth-migrations');

            $this->publishes([
                __DIR__ . '/../resources/views' => resource_path('views/vendor/center-auth'),
            ], 'center-auth-views');

            $this->commands([
                GenerateKeysCommand::class,
            ]);
        }

        $mode = strtolower((string) config('center-auth.mode', 'client'));

        if (in_array($mode, ['server', 'both'], true)) {
            $this->loadRoutesFrom(__DIR__ . '/../routes/server.php');

            if ((bool) config('center-auth.server.panel.enabled', false)) {
                $this->loadRoutesFrom(__DIR__ . '/../routes/panel.php');
            }
        }

        if (in_array($mode, ['client', 'both'], true)) {
            $this->loadRoutesFrom(__DIR__ . '/../routes/client.php');
            $this->app->make(Router::class)->aliasMiddleware('center-auth', AuthenticateWithCenterAuth::class);
        }
    }
}
