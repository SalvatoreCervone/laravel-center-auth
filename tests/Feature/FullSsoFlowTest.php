<?php

namespace CenterAuth\Tests\Feature;

use CenterAuth\Tests\Fixtures\User;
use CenterAuth\Tests\TestCase;
use Illuminate\Http\Client\Request as HttpClientRequest;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;

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
}
