<?php

namespace CenterAuth\Tests\Feature;

use CenterAuth\Data\AuthPayload;
use CenterAuth\Events\AuthenticationFailed;
use CenterAuth\Events\UserAuthenticated;
use CenterAuth\Facades\CenterAuth;
use CenterAuth\Tests\Fixtures\User;
use CenterAuth\Tests\TestCase;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;

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
}
