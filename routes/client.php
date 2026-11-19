<?php

use CenterAuth\Client\Http\Controllers\CallbackController;
use Illuminate\Support\Facades\Route;

$prefix = trim((string) config('center-auth.route_prefix', 'center-auth'), '/');

Route::prefix($prefix)
    ->name('center-auth.client.')
    ->group(function (): void {
        Route::get('/callback', CallbackController::class)
            ->middleware(config('center-auth.client.callback_middleware', ['web']))
            ->name('callback');
    });
