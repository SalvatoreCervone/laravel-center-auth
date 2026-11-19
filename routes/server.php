<?php

use CenterAuth\Server\Http\Controllers\ExchangeController;
use CenterAuth\Server\Http\Controllers\RedirectController;
use Illuminate\Support\Facades\Route;

$prefix = trim((string) config('center-auth.route_prefix', 'center-auth'), '/');

Route::prefix($prefix)
    ->name('center-auth.server.')
    ->group(function (): void {
        Route::get('/redirect/{client}', RedirectController::class)
            ->middleware(config('center-auth.server.redirect_middleware', ['web', 'auth']))
            ->name('redirect');

        Route::post('/exchange', ExchangeController::class)
            ->middleware(config('center-auth.server.exchange_middleware', ['throttle:60,1']))
            ->name('exchange');
    });
