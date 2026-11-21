<?php

namespace CenterAuth\Tests\Feature;

use CenterAuth\Events\CodeExchanged;
use CenterAuth\Events\CodeGenerated;
use CenterAuth\Facades\CenterAuth;
use CenterAuth\Tests\Fixtures\User;
use CenterAuth\Tests\TestCase;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;

class ServerAuthTest extends TestCase
{
    public function test_authenticated_user_is_redirected_to_client_with_one_time_code(): void
    {
        Event::fake([CodeGenerated::class]);

        $user = User::create([
            'name' => 'Mario Rossi',
            'email' => 'mario@example.com',
            'password' => Hash::make('secret'),
        ]);

        $response = $this->actingAs($user)
            ->get('/center-auth/redirect/app-alpha?page=/tickets/42');

        $response->assertRedirect();
        $location = $response->headers->get('Location');
        $this->assertNotNull($location);
        $this->assertStringStartsWith('https://alpha.test/center-auth/callback?code=', $location);

        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);
        $this->assertArrayHasKey('code', $query);
        $this->assertSame(64, strlen($query['code']));

        Event::assertDispatched(CodeGenerated::class, fn (CodeGenerated $e) => $e->clientId === 'app-alpha' && $e->targetPage === '/tickets/42');
    }

    public function test_guest_cannot_access_server_redirect_endpoint(): void
    {
        $this->getJson('/center-auth/redirect/app-alpha')
            ->assertUnauthorized();
    }

    public function test_unknown_client_returns_404(): void
    {
        $user = User::create([
            'name' => 'Mario Rossi',
            'email' => 'mario@example.com',
            'password' => Hash::make('secret'),
        ]);

        $this->actingAs($user)
            ->get('/center-auth/redirect/unknown-client')
            ->assertNotFound();
    }

    public function test_exchange_returns_signed_jwt_and_is_strictly_single_use(): void
    {
        Event::fake([CodeExchanged::class]);

        $user = User::create([
            'name' => 'Mario Rossi',
            'email' => 'mario@example.com',
            'password' => Hash::make('secret'),
        ]);

        $code = CenterAuth::server()->issueCode('app-alpha', $user, '/tickets/42');

        // First exchange succeeds
        $response = $this->withHeaders([
            'X-Center-Auth-Client-Id' => 'app-alpha',
            'X-Center-Auth-Client-Secret' => 'alpha-secret-123',
        ])->postJson('/center-auth/exchange', [
            'code' => $code,
        ]);

        $response->assertOk();
        $this->assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));

        $jwt = $response->json('jwt');
        $this->assertIsString($jwt);

        $decoded = JWT::decode($jwt, new Key(self::$testPublicKey, 'RS256'));
        $this->assertSame('https://auth.test', $decoded->iss);
        $this->assertSame((string) $user->id, $decoded->sub);
        $this->assertSame('app-alpha', $decoded->aud);
        $this->assertSame('/tickets/42', $decoded->page);
        $this->assertSame('mario@example.com', $decoded->user->email);
        $this->assertGreaterThan(time(), $decoded->exp);

        Event::assertDispatched(CodeExchanged::class, fn (CodeExchanged $e) => $e->clientId === 'app-alpha');

        // Second exchange with the same code MUST fail (single-use)
        $this->withHeaders([
            'X-Center-Auth-Client-Id' => 'app-alpha',
            'X-Center-Auth-Client-Secret' => 'alpha-secret-123',
        ])->postJson('/center-auth/exchange', [
            'code' => $code,
        ])->assertStatus(400);
    }

    public function test_exchange_rejects_invalid_client_secret(): void
    {
        $user = User::create([
            'name' => 'Mario Rossi',
            'email' => 'mario@example.com',
            'password' => Hash::make('secret'),
        ]);

        $code = CenterAuth::server()->issueCode('app-alpha', $user, '/');

        $this->withHeaders([
            'X-Center-Auth-Client-Id' => 'app-alpha',
            'X-Center-Auth-Client-Secret' => 'wrong-secret',
        ])->postJson('/center-auth/exchange', [
            'code' => $code,
        ])->assertUnauthorized();
    }

    public function test_exchange_rejects_code_issued_for_a_different_client_and_burns_it(): void
    {
        $user = User::create([
            'name' => 'Mario Rossi',
            'email' => 'mario@example.com',
            'password' => Hash::make('secret'),
        ]);

        $code = CenterAuth::server()->issueCode('app-alpha', $user, '/');

        // Client "app-beta" tries to redeem a code issued for "app-alpha"
        $this->withHeaders([
            'X-Center-Auth-Client-Id' => 'app-beta',
            'X-Center-Auth-Client-Secret' => 'beta-secret-456',
        ])->postJson('/center-auth/exchange', [
            'code' => $code,
        ])->assertUnauthorized();

        // Even the legitimate client can no longer use the burned code
        $this->withHeaders([
            'X-Center-Auth-Client-Id' => 'app-alpha',
            'X-Center-Auth-Client-Secret' => 'alpha-secret-123',
        ])->postJson('/center-auth/exchange', [
            'code' => $code,
        ])->assertStatus(400);
    }

    public function test_exchange_validates_missing_code(): void
    {
        $this->withHeaders([
            'X-Center-Auth-Client-Id' => 'app-alpha',
            'X-Center-Auth-Client-Secret' => 'alpha-secret-123',
        ])->postJson('/center-auth/exchange', [])
            ->assertUnprocessable();
    }

    public function test_reserved_jwt_claims_cannot_be_overwritten_and_custom_user_claims_hook_works(): void
    {
        $user = User::create([
            'name' => 'Mario Rossi',
            'email' => 'mario@example.com',
            'password' => Hash::make('secret'),
        ]);

        CenterAuth::resolveUserClaimsUsing(fn ($u, $clientId) => [
            'id' => $u->id,
            'name' => $u->name,
            'email' => $u->email,
            'department' => 'IT-' . $clientId,
        ]);

        $code = CenterAuth::server()->issueCode('app-alpha', $user, 'https://evil.com', [
            'iss' => 'https://attacker.com',
            'aud' => 'other-client',
            'custom_flag' => true,
        ]);

        $jwt = CenterAuth::server()->exchangeCode($code, 'app-alpha', 'alpha-secret-123');
        $decoded = JWT::decode($jwt, new Key(self::$testPublicKey, 'RS256'));

        $this->assertSame('https://auth.test', $decoded->iss);
        $this->assertSame('app-alpha', $decoded->aud);
        $this->assertSame('/', $decoded->page);
        $this->assertTrue($decoded->custom_flag);
        $this->assertSame('IT-app-alpha', $decoded->user->department);
    }

    public function test_jwt_is_signed_at_exchange_time_with_fresh_jwt_ttl(): void
    {
        config()->set('center-auth.server.code_ttl', 120);
        config()->set('center-auth.server.jwt_ttl', 10);

        $user = User::create([
            'name' => 'Mario Rossi',
            'email' => 'mario@example.com',
            'password' => Hash::make('secret'),
        ]);

        try {
            $issuedAt = Carbon::now();
            Carbon::setTestNow($issuedAt);

            $code = CenterAuth::server()->issueCode('app-alpha', $user, '/dashboard');

            // Advance 30s (past jwt_ttl=10s, still within code_ttl=120s)
            $exchangedAt = $issuedAt->copy()->addSeconds(30);
            Carbon::setTestNow($exchangedAt);
            JWT::$timestamp = $exchangedAt->getTimestamp();

            $response = $this->withHeaders([
                'X-Center-Auth-Client-Id' => 'app-alpha',
                'X-Center-Auth-Client-Secret' => 'alpha-secret-123',
            ])->postJson('/center-auth/exchange', [
                'code' => $code,
            ]);

            $response->assertOk();

            $decoded = JWT::decode($response->json('jwt'), new Key(self::$testPublicKey, 'RS256'));

            $this->assertSame($exchangedAt->getTimestamp(), $decoded->iat);
            $this->assertSame($exchangedAt->getTimestamp(), $decoded->nbf);
            $this->assertSame($exchangedAt->getTimestamp() + 10, $decoded->exp);
        } finally {
            Carbon::setTestNow();
            JWT::$timestamp = null;
        }
    }

    public function test_exchange_fails_immediately_when_code_lock_is_already_held(): void
    {
        $user = User::create([
            'name' => 'Mario Rossi',
            'email' => 'mario@example.com',
            'password' => Hash::make('secret'),
        ]);

        $code = CenterAuth::server()->issueCode('app-alpha', $user, '/');

        $store = Cache::store()->getStore();
        $this->assertInstanceOf(LockProvider::class, $store);

        $lock = $store->lock('center_auth_code_' . hash('sha256', $code) . ':lock', 5);
        $this->assertTrue($lock->get());

        try {
            $this->withHeaders([
                'X-Center-Auth-Client-Id' => 'app-alpha',
                'X-Center-Auth-Client-Secret' => 'alpha-secret-123',
            ])->postJson('/center-auth/exchange', [
                'code' => $code,
            ])->assertStatus(400);
        } finally {
            $lock->release();
        }
    }

    public function test_extra_claims_cannot_inject_data_or_overwrite_user_and_page_claims(): void
    {
        $user = User::create([
            'name' => 'Mario Rossi',
            'email' => 'mario@example.com',
            'password' => Hash::make('secret'),
        ]);

        $code = CenterAuth::server()->issueCode('app-alpha', $user, '/dashboard', [
            'data' => ['roles' => ['admin']],
            'user' => ['email' => 'attacker@evil.com'],
            'page' => '/admin',
            'tenant' => 'acme',
        ]);

        $jwt = CenterAuth::server()->exchangeCode($code, 'app-alpha', 'alpha-secret-123');
        $decoded = JWT::decode($jwt, new Key(self::$testPublicKey, 'RS256'));

        $this->assertFalse(property_exists($decoded, 'data'));
        $this->assertSame('mario@example.com', $decoded->user->email);
        $this->assertSame('/dashboard', $decoded->page);
        $this->assertSame('acme', $decoded->tenant);
    }
}
