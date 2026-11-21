<?php

namespace CenterAuth\Tests\Feature;

use CenterAuth\Facades\CenterAuth;
use CenterAuth\Models\CenterAuthClient;
use CenterAuth\Tests\Fixtures\User;
use CenterAuth\Tests\TestCase;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;

class ClientPanelTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('center-auth.server.client_driver', 'database');
        $app['config']->set('center-auth.server.panel.enabled', true);
        $app['config']->set('center-auth.server.panel.prefix', 'center-auth/admin');
    }

    protected function setUpDatabase(): void
    {
        parent::setUpDatabase();

        $migration = require __DIR__ . '/../../database/migrations/2026_01_01_000000_create_center_auth_clients_table.php';
        $migration->up();
    }

    private function createAdminUser(): User
    {
        return User::create([
            'name' => 'Admin',
            'email' => 'admin@example.com',
            'password' => Hash::make('secret'),
        ]);
    }

    public function test_panel_respects_custom_authorization_hook(): void
    {
        $admin = $this->createAdminUser();

        CenterAuth::authorizePanelUsing(fn () => false);

        $this->actingAs($admin)
            ->get('/center-auth/admin')
            ->assertForbidden();
    }

    public function test_panel_is_forbidden_by_default_in_non_local_environment(): void
    {
        $admin = $this->createAdminUser();

        $this->actingAs($admin)
            ->get('/center-auth/admin')
            ->assertForbidden();
    }

    public function test_panel_is_accessible_by_default_in_local_environment(): void
    {
        $admin = $this->createAdminUser();
        $this->app['env'] = 'local';

        $this->actingAs($admin)
            ->get('/center-auth/admin')
            ->assertOk();
    }

    public function test_panel_respects_configured_gate(): void
    {
        $admin = $this->createAdminUser();
        $regularUser = User::create([
            'name' => 'Regular User',
            'email' => 'user@example.com',
            'password' => Hash::make('secret'),
        ]);

        config()->set('center-auth.server.panel.gate', 'manage-center-auth');
        Gate::define('manage-center-auth', fn (User $user): bool => $user->email === 'admin@example.com');

        $this->actingAs($admin)
            ->get('/center-auth/admin')
            ->assertOk();

        $this->actingAs($regularUser)
            ->get('/center-auth/admin')
            ->assertForbidden();
    }

    public function test_can_create_client_via_panel_and_use_it_for_sso_exchange(): void
    {
        $admin = $this->createAdminUser();
        CenterAuth::authorizePanelUsing(fn () => true);

        $response = $this->actingAs($admin)
            ->post('/center-auth/admin/clients', [
                'name' => 'Portale Ticket',
                'client_id' => 'portale-ticket',
                'callback_url' => 'https://ticket.test/center-auth/callback',
                'description' => 'App gestione ticket',
                'is_active' => '1',
            ]);

        $response->assertRedirect('/center-auth/admin');
        $response->assertSessionHas('generated_client_id', 'portale-ticket');

        $plainSecret = session('generated_secret');
        $this->assertIsString($plainSecret);
        $this->assertSame(64, strlen($plainSecret));

        $client = CenterAuthClient::where('client_id', 'portale-ticket')->firstOrFail();
        $this->assertSame('Portale Ticket', $client->name);
        $this->assertTrue($client->is_active);
        $this->assertNotSame($plainSecret, $client->secret_hash);
        $this->assertTrue(Hash::check($plainSecret, $client->secret_hash));

        // Now verify the database-backed client works end-to-end with ServerAuthService
        $code = CenterAuth::server()->issueCode('portale-ticket', $admin, '/tickets');

        $this->withHeaders([
            'X-Center-Auth-Client-Id' => 'portale-ticket',
            'X-Center-Auth-Client-Secret' => $plainSecret,
        ])->postJson('/center-auth/exchange', [
            'code' => $code,
        ])->assertOk()->assertJsonStructure(['jwt']);

        $client->refresh();
        $this->assertNotNull($client->last_used_at);
    }

    public function test_can_edit_client_parameters_via_panel(): void
    {
        $admin = $this->createAdminUser();
        CenterAuth::authorizePanelUsing(fn () => true);

        $client = CenterAuthClient::create([
            'name' => 'App Vecchia',
            'client_id' => 'app-vecchia',
            'callback_url' => 'https://old.test/center-auth/callback',
            'description' => 'Vecchia descrizione',
            'is_active' => true,
            'secret_hash' => Hash::make('initial-secret'),
        ]);

        $this->actingAs($admin)
            ->get("/center-auth/admin/clients/{$client->id}/edit")
            ->assertOk()
            ->assertSee('App Vecchia');

        $this->actingAs($admin)
            ->put("/center-auth/admin/clients/{$client->id}", [
                'name' => 'App Nuova',
                'client_id' => 'app-nuova',
                'callback_url' => 'https://new.test/center-auth/callback',
                'description' => 'Descrizione aggiornata',
                'is_active' => '1',
            ])
            ->assertRedirect('/center-auth/admin');

        $client->refresh();
        $this->assertSame('App Nuova', $client->name);
        $this->assertSame('app-nuova', $client->client_id);
        $this->assertSame('https://new.test/center-auth/callback', $client->callback_url);
        $this->assertSame('Descrizione aggiornata', $client->description);
        $this->assertTrue($client->is_active);
    }

    public function test_toggling_client_immediately_blocks_and_restores_sso_access(): void
    {
        $admin = $this->createAdminUser();
        CenterAuth::authorizePanelUsing(fn () => true);
        $plainSecret = CenterAuthClient::generateSecret();

        $client = CenterAuthClient::create([
            'name' => 'App Test',
            'client_id' => 'app-test',
            'callback_url' => 'https://app.test/center-auth/callback',
            'is_active' => true,
            'secret_hash' => Hash::make($plainSecret),
        ]);

        // Issue a code while active
        $code = CenterAuth::server()->issueCode('app-test', $admin, '/home');

        // Disable the client from the panel
        $this->actingAs($admin)
            ->patch("/center-auth/admin/clients/{$client->id}/toggle")
            ->assertRedirect('/center-auth/admin');

        $client->refresh();
        $this->assertFalse($client->is_active);

        // Redirect endpoint rejects disabled client
        $this->actingAs($admin)
            ->get('/center-auth/redirect/app-test')
            ->assertNotFound();

        // Exchange endpoint rejects disabled client even with an existing code
        $this->withHeaders([
            'X-Center-Auth-Client-Id' => 'app-test',
            'X-Center-Auth-Client-Secret' => $plainSecret,
        ])->postJson('/center-auth/exchange', [
            'code' => $code,
        ])->assertUnauthorized();

        // Re-enable the client from the panel
        $this->actingAs($admin)
            ->patch("/center-auth/admin/clients/{$client->id}/toggle")
            ->assertRedirect('/center-auth/admin');

        $client->refresh();
        $this->assertTrue($client->is_active);

        // Now redirect works again
        $this->actingAs($admin)
            ->get('/center-auth/redirect/app-test')
            ->assertRedirect();
    }

    public function test_secret_rotation_supports_grace_window_and_immediate_revocation(): void
    {
        $admin = $this->createAdminUser();
        CenterAuth::authorizePanelUsing(fn () => true);
        $oldSecret = CenterAuthClient::generateSecret();

        $client = CenterAuthClient::create([
            'name' => 'App Rotazione',
            'client_id' => 'app-rotazione',
            'callback_url' => 'https://rot.test/center-auth/callback',
            'is_active' => true,
            'secret_hash' => Hash::make($oldSecret),
        ]);

        // Rotate with 24h grace window
        $this->actingAs($admin)
            ->post("/center-auth/admin/clients/{$client->id}/rotate-secret", [
                'grace_hours' => 24,
            ])
            ->assertRedirect('/center-auth/admin');

        $newSecret = session('generated_secret');
        $this->assertIsString($newSecret);
        $this->assertNotSame($oldSecret, $newSecret);

        // Both old and new secrets work during the grace window
        $code1 = CenterAuth::server()->issueCode('app-rotazione', $admin, '/a');
        $this->withHeaders([
            'X-Center-Auth-Client-Id' => 'app-rotazione',
            'X-Center-Auth-Client-Secret' => $oldSecret,
        ])->postJson('/center-auth/exchange', ['code' => $code1])->assertOk();

        $code2 = CenterAuth::server()->issueCode('app-rotazione', $admin, '/b');
        $this->withHeaders([
            'X-Center-Auth-Client-Id' => 'app-rotazione',
            'X-Center-Auth-Client-Secret' => $newSecret,
        ])->postJson('/center-auth/exchange', ['code' => $code2])->assertOk();

        // Rotate with 0h grace window -> immediate revocation of previous secret
        $this->actingAs($admin)
            ->post("/center-auth/admin/clients/{$client->id}/rotate-secret", [
                'grace_hours' => 0,
            ])
            ->assertRedirect('/center-auth/admin');

        $latestSecret = session('generated_secret');

        $code3 = CenterAuth::server()->issueCode('app-rotazione', $admin, '/c');
        $this->withHeaders([
            'X-Center-Auth-Client-Id' => 'app-rotazione',
            'X-Center-Auth-Client-Secret' => $newSecret,
        ])->postJson('/center-auth/exchange', ['code' => $code3])->assertUnauthorized();

        $this->withHeaders([
            'X-Center-Auth-Client-Id' => 'app-rotazione',
            'X-Center-Auth-Client-Secret' => $latestSecret,
        ])->postJson('/center-auth/exchange', ['code' => $code3])->assertOk();
    }

    public function test_can_delete_client_via_panel(): void
    {
        $admin = $this->createAdminUser();
        CenterAuth::authorizePanelUsing(fn () => true);

        $client = CenterAuthClient::create([
            'name' => 'App Da Eliminare',
            'client_id' => 'app-delete',
            'callback_url' => 'https://del.test/center-auth/callback',
            'is_active' => true,
            'secret_hash' => Hash::make('secret'),
        ]);

        $this->actingAs($admin)
            ->delete("/center-auth/admin/clients/{$client->id}")
            ->assertRedirect('/center-auth/admin');

        $this->assertDatabaseMissing('center_auth_clients', ['id' => $client->id]);
    }

    public function test_confirm_dialogs_safely_escape_special_characters_and_newlines(): void
    {
        $admin = $this->createAdminUser();
        CenterAuth::authorizePanelUsing(fn () => true);

        $client = CenterAuthClient::create([
            'name' => "App \"Test\" 'O'Reilly'\nLine2",
            'client_id' => 'app-special',
            'callback_url' => 'https://special.test/center-auth/callback',
            'is_active' => true,
            'secret_hash' => Hash::make('secret'),
        ]);

        $this->actingAs($admin)
            ->get('/center-auth/admin')
            ->assertOk()
            ->assertSee('onsubmit="return confirm(this.dataset.confirm);"', false)
            ->assertSee("data-confirm=\"Eliminare definitivamente l'applicazione App &quot;Test&quot; &#039;O&#039;Reilly&#039;\nLine2?\"", false)
            ->assertDontSee('App "Test"', false);

        $this->actingAs($admin)
            ->get("/center-auth/admin/clients/{$client->id}/edit")
            ->assertOk()
            ->assertSee('onsubmit="return confirm(this.dataset.confirm);"', false)
            ->assertSee("data-confirm=\"Generare un nuovo secret per App &quot;Test&quot; &#039;O&#039;Reilly&#039;\nLine2?\"", false)
            ->assertDontSee('App "Test"', false);
    }

    public function test_panel_index_shows_warning_banner_when_config_driver_has_no_table(): void
    {
        $admin = $this->createAdminUser();
        CenterAuth::authorizePanelUsing(fn () => true);

        config()->set('center-auth.server.client_driver', 'config');
        Schema::dropIfExists('center_auth_clients');

        $this->actingAs($admin)
            ->get('/center-auth/admin')
            ->assertOk()
            ->assertSee('CENTER_AUTH_CLIENT_DRIVER=database');
    }
}
