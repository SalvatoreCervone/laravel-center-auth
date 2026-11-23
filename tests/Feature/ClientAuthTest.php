<?php

namespace CenterAuth\Tests\Feature;

use CenterAuth\Client\UserSynchronizer;
use CenterAuth\Data\AuthPayload;
use CenterAuth\Events\AuthenticationFailed;
use CenterAuth\Events\UserAuthenticated;
use CenterAuth\Exceptions\InvalidConfigurationException;
use CenterAuth\Facades\CenterAuth;
use CenterAuth\Tests\Fixtures\User;
use CenterAuth\Tests\TestCase;
use Firebase\JWT\JWT;
use Illuminate\Http\Client\Request as HttpClientRequest;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;

class ClientAuthTest extends TestCase
{
    public function test_missing_code_redirects_to_trusted_fallback_and_ignores_query_redirect_fallback(): void
    {
        Event::fake([AuthenticationFailed::class]);

        $response = $this->get('/center-auth/callback?redirect_fallback=https://evil.com');

        $response->assertRedirect('https://auth.test/login');
        $this->assertGuest();
        Event::assertDispatched(AuthenticationFailed::class);
    }

    public function test_failed_exchange_redirects_to_trusted_fallback(): void
    {
        Event::fake([AuthenticationFailed::class]);

        Http::fake([
            'https://auth.test/center-auth/exchange' => Http::response(['message' => 'Invalid code'], 400),
        ]);

        $response = $this->get('/center-auth/callback?code=expired-code');

        $response->assertRedirect('https://auth.test/login');
        $this->assertGuest();
        Event::assertDispatched(AuthenticationFailed::class);
    }

    public function test_rejects_jwt_signed_with_wrong_private_key(): void
    {
        Event::fake([AuthenticationFailed::class]);

        $rogueKey = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        openssl_pkey_export($rogueKey, $roguePrivatePem);

        $jwt = JWT::encode([
            'iss' => 'https://auth.test',
            'sub' => '1',
            'aud' => 'app-alpha',
            'iat' => time(),
            'exp' => time() + 60,
            'jti' => 'jti-rogue',
            'page' => '/dashboard',
            'user' => ['id' => 1, 'name' => 'Attacker', 'email' => 'attacker@example.com'],
        ], $roguePrivatePem, 'RS256');

        Http::fake([
            'https://auth.test/center-auth/exchange' => Http::response(['jwt' => $jwt], 200),
        ]);

        $this->get('/center-auth/callback?code=valid-code')
            ->assertRedirect('https://auth.test/login');

        $this->assertGuest();
        Event::assertDispatched(AuthenticationFailed::class);
    }

    public function test_rejects_jwt_with_wrong_audience(): void
    {
        Event::fake([AuthenticationFailed::class]);

        $jwt = JWT::encode([
            'iss' => 'https://auth.test',
            'sub' => '1',
            'aud' => 'app-beta', // wrong audience (this client is app-alpha)
            'iat' => time(),
            'exp' => time() + 60,
            'jti' => 'jti-1',
            'page' => '/dashboard',
            'user' => ['id' => 1, 'name' => 'Mario', 'email' => 'mario@example.com'],
        ], self::$testPrivateKey, 'RS256');

        Http::fake([
            'https://auth.test/center-auth/exchange' => Http::response(['jwt' => $jwt], 200),
        ]);

        $this->get('/center-auth/callback?code=valid-code')
            ->assertRedirect('https://auth.test/login');

        $this->assertGuest();
        Event::assertDispatched(AuthenticationFailed::class);
    }

    public function test_rejects_expired_jwt(): void
    {
        Event::fake([AuthenticationFailed::class]);

        $jwt = JWT::encode([
            'iss' => 'https://auth.test',
            'sub' => '1',
            'aud' => 'app-alpha',
            'iat' => time() - 120,
            'exp' => time() - 10,
            'jti' => 'jti-expired',
            'page' => '/dashboard',
            'user' => ['id' => 1, 'name' => 'Mario', 'email' => 'mario@example.com'],
        ], self::$testPrivateKey, 'RS256');

        Http::fake([
            'https://auth.test/center-auth/exchange' => Http::response(['jwt' => $jwt], 200),
        ]);

        $this->get('/center-auth/callback?code=valid-code')
            ->assertRedirect('https://auth.test/login');

        $this->assertGuest();
        Event::assertDispatched(AuthenticationFailed::class);
    }

    public function test_rejects_jwt_with_wrong_issuer(): void
    {
        Event::fake([AuthenticationFailed::class]);

        $jwt = JWT::encode([
            'iss' => 'https://rogue-issuer.test',
            'sub' => '1',
            'aud' => 'app-alpha',
            'iat' => time(),
            'exp' => time() + 60,
            'jti' => 'jti-issuer',
            'page' => '/dashboard',
            'user' => ['id' => 1, 'name' => 'Mario', 'email' => 'mario@example.com'],
        ], self::$testPrivateKey, 'RS256');

        Http::fake([
            'https://auth.test/center-auth/exchange' => Http::response(['jwt' => $jwt], 200),
        ]);

        $this->get('/center-auth/callback?code=valid-code')
            ->assertRedirect('https://auth.test/login');

        $this->assertGuest();
    }

    public function test_valid_callback_creates_user_with_random_password_and_logs_in(): void
    {
        Event::fake([UserAuthenticated::class]);

        $jwt = JWT::encode([
            'iss' => 'https://auth.test',
            'sub' => '99',
            'aud' => 'app-alpha',
            'iat' => time(),
            'exp' => time() + 60,
            'jti' => 'jti-ok',
            'page' => '/tickets/new',
            'user' => ['id' => 99, 'name' => 'Giulia Bianchi', 'email' => 'giulia@example.com'],
        ], self::$testPrivateKey, 'RS256');

        Http::fake([
            'https://auth.test/center-auth/exchange' => Http::response(['jwt' => $jwt], 200),
        ]);

        $response = $this->get('/center-auth/callback?code=valid-code');

        $response->assertRedirect('/tickets/new');
        $this->assertAuthenticated();

        $user = User::where('email', 'giulia@example.com')->firstOrFail();
        $this->assertSame('Giulia Bianchi', $user->name);
        $this->assertFalse(Hash::check('test', $user->password));
        $this->assertSame('https://auth.test', session('center_auth.issuer'));

        Event::assertDispatched(UserAuthenticated::class, fn (UserAuthenticated $e) => $e->user->getAuthIdentifier() === $user->id);
    }

    public function test_existing_user_password_is_preserved_on_subsequent_logins(): void
    {
        $existing = User::create([
            'name' => 'Old Name',
            'email' => 'giulia@example.com',
            'password' => Hash::make('my-real-password'),
        ]);

        $jwt = JWT::encode([
            'iss' => 'https://auth.test',
            'sub' => '99',
            'aud' => 'app-alpha',
            'iat' => time(),
            'exp' => time() + 60,
            'jti' => 'jti-ok-2',
            'page' => '/home',
            'user' => ['id' => 99, 'name' => 'New Name', 'email' => 'giulia@example.com'],
        ], self::$testPrivateKey, 'RS256');

        Http::fake([
            'https://auth.test/center-auth/exchange' => Http::response(['jwt' => $jwt], 200),
        ]);

        $this->get('/center-auth/callback?code=valid-code')
            ->assertRedirect('/home');

        $existing->refresh();
        $this->assertSame('New Name', $existing->name);
        $this->assertTrue(Hash::check('my-real-password', $existing->password));
    }

    public function test_before_login_hook_can_deny_authentication(): void
    {
        Event::fake([AuthenticationFailed::class]);

        CenterAuth::beforeLoginUsing(function ($user, AuthPayload $payload) {
            return $payload->page !== '/admin-only';
        });

        $jwt = JWT::encode([
            'iss' => 'https://auth.test',
            'sub' => '99',
            'aud' => 'app-alpha',
            'iat' => time(),
            'exp' => time() + 60,
            'jti' => 'jti-denied',
            'page' => '/admin-only',
            'user' => ['id' => 99, 'name' => 'Giulia', 'email' => 'giulia@example.com'],
        ], self::$testPrivateKey, 'RS256');

        Http::fake([
            'https://auth.test/center-auth/exchange' => Http::response(['jwt' => $jwt], 200),
        ]);

        $this->get('/center-auth/callback?code=valid-code')
            ->assertRedirect('https://auth.test/login');

        $this->assertGuest();
        Event::assertDispatched(AuthenticationFailed::class);
    }

    public function test_custom_user_resolver_is_invoked(): void
    {
        $preexisting = User::create([
            'name' => 'Mapped User',
            'email' => 'mapped@example.com',
            'password' => Hash::make('secret'),
        ]);

        CenterAuth::resolveUserUsing(fn (AuthPayload $payload) => $preexisting);

        $jwt = JWT::encode([
            'iss' => 'https://auth.test',
            'sub' => '99',
            'aud' => 'app-alpha',
            'iat' => time(),
            'exp' => time() + 60,
            'jti' => 'jti-custom',
            'page' => '/custom',
            'user' => ['id' => 99, 'name' => 'Someone Else', 'email' => 'other@example.com'],
        ], self::$testPrivateKey, 'RS256');

        Http::fake([
            'https://auth.test/center-auth/exchange' => Http::response(['jwt' => $jwt], 200),
        ]);

        $this->get('/center-auth/callback?code=valid-code')
            ->assertRedirect('/custom');

        $this->assertAuthenticatedAs($preexisting);
        $this->assertNull(User::where('email', 'other@example.com')->first());
    }

    public function test_verify_jwt_throws_when_server_url_is_empty_and_callback_fails_safely(): void
    {
        Event::fake([AuthenticationFailed::class]);

        config()->set('center-auth.client.server_url', '');
        config()->set('center-auth.client.server_api_url', 'https://auth.test');

        $jwt = JWT::encode([
            'iss' => 'https://auth.test',
            'sub' => '1',
            'aud' => 'app-alpha',
            'iat' => time(),
            'exp' => time() + 60,
            'jti' => 'jti-empty-server-url',
            'page' => '/dashboard',
            'user' => ['id' => 1, 'name' => 'Mario', 'email' => 'mario@example.com'],
        ], self::$testPrivateKey, 'RS256');

        Http::fake([
            'https://auth.test/center-auth/exchange' => Http::response(['jwt' => $jwt], 200),
        ]);

        // Callback fails safely (InvalidConfigurationException extends CenterAuthException)
        $this->get('/center-auth/callback?code=valid-code')
            ->assertRedirect('https://auth.test/login');

        $this->assertGuest();
        Event::assertDispatched(AuthenticationFailed::class);

        // Direct verifyJwt() call throws InvalidConfigurationException
        $this->expectException(InvalidConfigurationException::class);

        CenterAuth::client()->verifyJwt($jwt);
    }

    public function test_user_synchronizer_handles_concurrent_insert_race_condition(): void
    {
        $payload = new AuthPayload(
            sub: '42',
            email: 'race@example.com',
            name: 'Race User',
            page: '/dashboard',
            issuer: 'https://auth.test',
            audience: 'app-alpha',
            jti: 'jti-race',
            issuedAt: time(),
            expiresAt: time() + 60,
            userData: ['id' => 42, 'name' => 'Race User', 'email' => 'race@example.com'],
            claims: [],
        );

        $raced = false;
        User::creating(function (User $model) use (&$raced): void {
            if (! $raced && $model->email === 'race@example.com') {
                $raced = true;
                DB::table('users')->insert([
                    'name' => 'Concurrent User',
                    'email' => 'race@example.com',
                    'password' => Hash::make('concurrent-secret'),
                    'created_at' => now(),
                    'updated_at' => now(),
                ]);
            }
        });

        try {
            /** @var User $synced */
            $synced = app(UserSynchronizer::class)->sync($payload);
        } finally {
            User::flushEventListeners();
        }

        $this->assertTrue($raced);
        $this->assertSame('race@example.com', $synced->email);
        $this->assertSame('Concurrent User', $synced->name);
        $this->assertSame(1, User::where('email', 'race@example.com')->count());
    }

    public function test_exchange_code_avoids_double_slash_when_route_prefix_is_empty_or_slash(): void
    {
        Http::fake([
            'https://auth.test/exchange' => Http::response(['jwt' => 'signed-jwt-token'], 200),
        ]);

        foreach (['', '/'] as $prefix) {
            config()->set('center-auth.route_prefix', $prefix);

            $jwt = CenterAuth::client()->exchangeCode('valid-code');

            $this->assertSame('signed-jwt-token', $jwt);
        }

        Http::assertSentCount(2);
        Http::assertSent(fn (HttpClientRequest $request) => $request->url() === 'https://auth.test/exchange');
        Http::assertNotSent(fn (HttpClientRequest $request) => str_contains($request->url(), '//exchange'));
    }

    public function test_center_auth_middleware_redirects_guest_to_server_with_requested_path_and_query(): void
    {
        Route::middleware(['web', 'center-auth'])
            ->get('/orders/{id}', fn (string $id) => "order-{$id}");

        $response = $this->get('/orders/42?tab=details&sort=asc');

        $response->assertRedirect(
            'https://auth.test/center-auth/redirect/app-alpha?page=' . urlencode('/orders/42?tab=details&sort=asc')
        );
    }

    public function test_center_auth_middleware_allows_authenticated_user(): void
    {
        Route::middleware(['web', 'center-auth'])
            ->get('/orders/42', fn () => 'secret-order');

        $user = User::create([
            'name' => 'Mario',
            'email' => 'mario@example.com',
            'password' => Hash::make('secret'),
        ]);

        $this->actingAs($user)
            ->get('/orders/42')
            ->assertOk()
            ->assertSee('secret-order');
    }

    public function test_center_auth_middleware_uses_default_redirect_for_non_get_requests(): void
    {
        config()->set('center-auth.client.default_redirect', '/dashboard');

        Route::middleware(['center-auth'])
            ->post('/orders', fn () => 'created');

        $this->post('/orders')
            ->assertRedirect(
                'https://auth.test/center-auth/redirect/app-alpha?page=' . urlencode('/dashboard')
            );
    }

    public function test_center_auth_middleware_returns_401_for_json_requests(): void
    {
        Route::middleware(['center-auth'])
            ->get('/api/orders', fn () => ['ok' => true]);

        $this->getJson('/api/orders')
            ->assertUnauthorized()
            ->assertJson(['message' => 'Unauthenticated.']);
    }

    public function test_build_server_redirect_url_sanitizes_page_and_requires_configuration(): void
    {
        $url = CenterAuth::client()->buildServerRedirectUrl('https://evil.com/phish');
        $this->assertSame('https://auth.test/center-auth/redirect/app-alpha?page=%2F', $url);

        config()->set('center-auth.client.server_url', '');

        $this->expectException(InvalidConfigurationException::class);
        CenterAuth::client()->buildServerRedirectUrl('/dashboard');
    }
}
