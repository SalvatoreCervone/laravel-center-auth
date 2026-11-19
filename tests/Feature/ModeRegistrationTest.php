<?php

namespace CenterAuth\Tests\Feature;

use CenterAuth\Tests\TestCase;
use Illuminate\Support\Facades\Route;

class ModeRegistrationTest extends TestCase
{
    public function test_both_mode_registers_server_and_client_routes(): void
    {
        $this->assertTrue(Route::has('center-auth.server.redirect'));
        $this->assertTrue(Route::has('center-auth.server.exchange'));
        $this->assertTrue(Route::has('center-auth.client.callback'));
    }
}
