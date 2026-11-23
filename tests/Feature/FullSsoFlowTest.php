<?php

namespace CenterAuth\Tests\Feature;

use CenterAuth\Tests\Fixtures\User;
use CenterAuth\Tests\TestCase;
use Illuminate\Http\Client\Request as HttpClientRequest;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;

class FullSsoFlowTest extends TestCase
{
    public function test_complete_end_to_end_sso_flow_from_server_redirect_to_client_login(): void
    {
        // 1. User is authenticated on the central server
        $serverUser = User::create([
            'name' => 'Salvatore',
            'email' => 'salvatore@example.com',
            'password' => Hash::make('server-secret'),
        ]);

        // 2. Server issues a one-time code and redirects to the client callback URL
        $redirectResponse = $this->actingAs($serverUser)
            ->get('/center-auth/redirect/app-alpha?page=' . urlencode('/records/list?status=open'));

        $redirectResponse->assertRedirect();
        $location = (string) $redirectResponse->headers->get('Location');
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);
        $code = $query['code'] ?? '';
        $this->assertNotEmpty($code);

        // Simulate switching to the client app (logged out initially)
        Auth::logout();
        $this->assertGuest();

        // 3. Wire the client's back-channel HTTP POST /exchange directly to the real server endpoint
        Http::fake(function (HttpClientRequest $request) {
            if ($request->url() === 'https://auth.test/center-auth/exchange') {
                $exchangeResponse = $this->withHeaders([
                    'X-Center-Auth-Client-Id' => $request->header('X-Center-Auth-Client-Id')[0] ?? '',
                    'X-Center-Auth-Client-Secret' => $request->header('X-Center-Auth-Client-Secret')[0] ?? '',
                ])->postJson('/center-auth/exchange', $request->data());

                return Http::response($exchangeResponse->json(), $exchangeResponse->status());
            }

            return Http::response(['message' => 'Unexpected URL'], 500);
        });

        // 4. Client handles /center-auth/callback?code=...
        $callbackResponse = $this->get('/center-auth/callback?code=' . urlencode($code));

        $callbackResponse->assertRedirect('/records/list?status=open');
        $this->assertAuthenticated();
        $this->assertSame('salvatore@example.com', Auth::user()->email);

        // 5. Replaying the exact same callback URL MUST fail (code already consumed)
        Auth::logout();
        $replayResponse = $this->get('/center-auth/callback?code=' . urlencode($code));
        $replayResponse->assertRedirect('https://auth.test/login');
        $this->assertGuest();
    }

    public function test_complete_client_initiated_sso_flow_through_server_login_and_back_to_requested_page(): void
    {
        // Client protected route
        Route::middleware(['web', 'center-auth'])
            ->get('/pagina-x', fn () => 'contenuto-pagina-x');

        // Simulated Server login routes (standard Laravel redirect()->intended())
        $serverUser = User::create([
            'name' => 'Salvatore',
            'email' => 'salvatore@example.com',
            'password' => Hash::make('server-secret'),
        ]);

        Route::middleware('web')->get('/login', fn () => 'server-login-form')->name('login');
        Route::middleware('web')->post('/login', function () use ($serverUser) {
            Auth::login($serverUser);

            return redirect()->intended('/');
        });

        // 1. Guest visits client URL directly -> redirected to Server /center-auth/redirect/{client}?page=...
        $clientHit = $this->get('/pagina-x?tab=dettagli');
        $clientHit->assertRedirect(
            'https://auth.test/center-auth/redirect/app-alpha?page=' . urlencode('/pagina-x?tab=dettagli')
        );

        $serverRedirectPath = parse_url((string) $clientHit->headers->get('Location'), PHP_URL_PATH)
            . '?' . parse_url((string) $clientHit->headers->get('Location'), PHP_URL_QUERY);

        // 2. Guest arrives on Server /center-auth/redirect/app-alpha?page=... -> Server redirects to /login saving intended URL
        $serverGuestHit = $this->get($serverRedirectPath);
        $serverGuestHit->assertRedirect(route('login'));

        // 3. User logs in on Server -> redirect()->intended() resumes /center-auth/redirect/app-alpha?page=...
        $loginResponse = $this->post('/login');
        $loginResponse->assertRedirect(url($serverRedirectPath));

        // 4. Following intended redirect on Server issues one-time code -> redirects to Client /callback?code=...
        $serverCodeResponse = $this->get((string) $loginResponse->headers->get('Location'));
        $serverCodeResponse->assertRedirect();
        $callbackLocation = (string) $serverCodeResponse->headers->get('Location');
        parse_str((string) parse_url($callbackLocation, PHP_URL_QUERY), $query);
        $code = $query['code'] ?? '';
        $this->assertNotEmpty($code);

        // Switch to unauthenticated client session
        Auth::logout();
        $this->assertGuest();

        // Wire back-channel /exchange to real server endpoint
        Http::fake(function (HttpClientRequest $request) {
            if ($request->url() === 'https://auth.test/center-auth/exchange') {
                $exchangeResponse = $this->withHeaders([
                    'X-Center-Auth-Client-Id' => $request->header('X-Center-Auth-Client-Id')[0] ?? '',
                    'X-Center-Auth-Client-Secret' => $request->header('X-Center-Auth-Client-Secret')[0] ?? '',
                ])->postJson('/center-auth/exchange', $request->data());

                return Http::response($exchangeResponse->json(), $exchangeResponse->status());
            }

            return Http::response(['message' => 'Unexpected URL'], 500);
        });

        // 5. Client callback exchanges code, logs user in, and redirects to the originally requested /pagina-x?tab=dettagli
        $callbackResponse = $this->get('/center-auth/callback?code=' . urlencode($code));
        $callbackResponse->assertRedirect('/pagina-x?tab=dettagli');
        $this->assertAuthenticated();

        // 6. User can now access the protected client page
        $this->get('/pagina-x?tab=dettagli')
            ->assertOk()
            ->assertSee('contenuto-pagina-x');
    }
}
