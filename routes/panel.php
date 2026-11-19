<?php

use CenterAuth\Server\Http\Controllers\ClientPanelController;
use CenterAuth\Server\Http\Middleware\AuthorizePanel;
use Illuminate\Support\Facades\Route;

$prefix = trim((string) config('center-auth.server.panel.prefix', 'center-auth/admin'), '/');
$middleware = array_merge(
    (array) config('center-auth.server.panel.middleware', ['web', 'auth']),
    [AuthorizePanel::class]
);

Route::prefix($prefix)
    ->middleware($middleware)
    ->name('center-auth.panel.')
    ->group(function (): void {
        Route::get('/', [ClientPanelController::class, 'index'])->name('index');
        Route::get('/clients/create', [ClientPanelController::class, 'create'])->name('clients.create');
        Route::post('/clients', [ClientPanelController::class, 'store'])->name('clients.store');
        Route::get('/clients/{client}/edit', [ClientPanelController::class, 'edit'])->name('clients.edit');
        Route::put('/clients/{client}', [ClientPanelController::class, 'update'])->name('clients.update');
        Route::patch('/clients/{client}/toggle', [ClientPanelController::class, 'toggle'])->name('clients.toggle');
        Route::post('/clients/{client}/rotate-secret', [ClientPanelController::class, 'rotateSecret'])->name('clients.rotate-secret');
        Route::delete('/clients/{client}', [ClientPanelController::class, 'destroy'])->name('clients.destroy');
    });
