<?php

namespace CenterAuth\Client;

use CenterAuth\CenterAuthManager;
use CenterAuth\Data\AuthPayload;
use CenterAuth\Events\AuthenticationFailed;
use CenterAuth\Events\UserAuthenticated;
use CenterAuth\Exceptions\CenterAuthException;
use CenterAuth\Exceptions\CodeExchangeException;
use CenterAuth\Exceptions\InvalidConfigurationException;
use CenterAuth\Exceptions\InvalidTokenException;
use CenterAuth\Support\KeyLoader;
use CenterAuth\Support\PathSanitizer;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Throwable;

class ClientAuthService
{
    public function __construct(
        private readonly KeyLoader $keyLoader,
        private readonly UserSynchronizer $userSynchronizer,
        private readonly CenterAuthManager $manager,
    ) {
    }

    /**
     * Exchange a one-time authorization code with the central auth server via back-channel POST.
     */
    public function exchangeCode(string $code): string
    {
        $clientId = (string) config('center-auth.client.client_id', '');
        $clientSecret = (string) config('center-auth.client.client_secret', '');
        $apiBaseUrl = rtrim(
            (string) (config('center-auth.client.server_api_url') ?: config('center-auth.client.server_url', '')),
            '/'
        );
        $prefix = trim((string) config('center-auth.route_prefix', 'center-auth'), '/');

        if ($clientId === '' || $clientSecret === '' || $apiBaseUrl === '') {
            throw new InvalidConfigurationException(
                'CenterAuth client requires client_id, client_secret, and server_url (or server_api_url).'
            );
        }

        $options = [
            'verify' => (bool) config('center-auth.client.verify_ssl', true),
        ];

        $proxy = config('center-auth.client.http_proxy');
        if ($proxy !== null) {
            $options['proxy'] = $proxy;
        }

        $timeout = max(1, (int) config('center-auth.client.http_timeout', 10));
        $exchangeUrl = "{$apiBaseUrl}/{$prefix}/exchange";

        try {
            $response = Http::withOptions($options)
                ->timeout($timeout)
                ->acceptJson()
                ->withHeaders([
                    'X-Center-Auth-Client-Id' => $clientId,
                    'X-Center-Auth-Client-Secret' => $clientSecret,
                ])
                ->post($exchangeUrl, [
                    'code' => $code,
                ]);
        } catch (Throwable $e) {
            throw new CodeExchangeException('Failed to contact CenterAuth server: ' . $e->getMessage(), 0, $e);
        }

        if ($response->failed()) {
            $message = (string) ($response->json('message') ?? "HTTP {$response->status()}");
            throw new CodeExchangeException("CenterAuth code exchange failed: {$message}");
        }

        $jwt = $response->json('jwt');

        if (! is_string($jwt) || trim($jwt) === '') {
            throw new CodeExchangeException('CenterAuth server returned an invalid or empty JWT.');
        }

        return $jwt;
    }

    /**
     * Verify the JWT signature, expiration, issuer, and audience claims.
     */
    public function verifyJwt(string $jwt): AuthPayload
    {
        $publicKey = $this->keyLoader->loadPublicKey();
        $algorithm = (string) config('center-auth.keys.algorithm', 'RS256');

        try {
            $decoded = JWT::decode($jwt, new Key($publicKey, $algorithm));
        } catch (Throwable $e) {
            throw new InvalidTokenException('Invalid or expired JWT: ' . $e->getMessage(), 0, $e);
        }

        $claims = json_decode(json_encode($decoded, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);

        $expectedClientId = (string) config('center-auth.client.client_id', '');
        $actualAudience = (string) ($claims['aud'] ?? '');

        if ($expectedClientId === '' || $actualAudience === '' || ! hash_equals($expectedClientId, $actualAudience)) {
            throw new InvalidTokenException('JWT audience (aud) does not match this client.');
        }

        $expectedIssuer = rtrim((string) config('center-auth.client.server_url', ''), '/');
        $actualIssuer = rtrim((string) ($claims['iss'] ?? ''), '/');

        if ($expectedIssuer !== '' && ($actualIssuer === '' || ! hash_equals($expectedIssuer, $actualIssuer))) {
            throw new InvalidTokenException('JWT issuer (iss) does not match configured server_url.');
        }

        $sub = (string) ($claims['sub'] ?? '');
        $userData = is_array($claims['user'] ?? null) ? $claims['user'] : [];
        $email = (string) ($userData['email'] ?? '');
        $name = (string) ($userData['name'] ?? '');

        if ($sub === '' || $email === '') {
            throw new InvalidTokenException('JWT is missing required subject (sub) or user email claims.');
        }

        $defaultRedirect = (string) config('center-auth.client.default_redirect', '/');
        $page = PathSanitizer::sanitize(
            is_string($claims['page'] ?? null) ? $claims['page'] : null,
            $defaultRedirect
        );

        return new AuthPayload(
            sub: $sub,
            email: $email,
            name: $name,
            page: $page,
            issuer: $actualIssuer,
            audience: $actualAudience,
            jti: (string) ($claims['jti'] ?? ''),
            issuedAt: (int) ($claims['iat'] ?? 0),
            expiresAt: (int) ($claims['exp'] ?? 0),
            userData: $userData,
            claims: $claims,
        );
    }

    /**
     * Resolve/sync the local user, invoke beforeLogin hook, authenticate the session,
     * and regenerate the session ID to prevent session fixation.
     */
    public function authenticate(AuthPayload $payload, Request $request): Authenticatable
    {
        $resolver = $this->manager->getUserResolver();
        $user = $resolver !== null
            ? $resolver($payload)
            : $this->userSynchronizer->sync($payload);

        if (! $user instanceof Authenticatable) {
            throw new CenterAuthException('Resolved user must implement Illuminate\\Contracts\\Auth\\Authenticatable.');
        }

        if (! $this->manager->runBeforeLogin($user, $payload, $request)) {
            throw new CenterAuthException('Authentication denied by beforeLogin hook.');
        }

        $guard = config('center-auth.client.guard');
        Auth::guard($guard)->login($user);

        if ($request->hasSession()) {
            $request->session()->regenerate();
            $request->session()->put('center_auth.issuer', $payload->issuer);
            $request->session()->put('center_auth.authenticated_at', time());
        }

        UserAuthenticated::dispatch($user, $payload, $request);

        return $user;
    }

    /**
     * Handle the incoming /callback HTTP request end-to-end.
     */
    public function handleCallback(Request $request): RedirectResponse
    {
        $code = $request->query('code');

        if (! is_string($code) || trim($code) === '') {
            AuthenticationFailed::dispatch('Missing authorization code.', $request);

            return redirect()->to($this->fallbackUrl());
        }

        try {
            $jwt = $this->exchangeCode($code);
            $payload = $this->verifyJwt($jwt);
            $this->authenticate($payload, $request);

            return redirect()->to($payload->page);
        } catch (CenterAuthException $e) {
            Log::warning('CenterAuth callback authentication failed.', [
                'error' => $e->getMessage(),
                'ip' => $request->ip(),
            ]);

            AuthenticationFailed::dispatch($e->getMessage(), $request, $e);

            return redirect()->to($this->fallbackUrl());
        }
    }

    public function fallbackUrl(): string
    {
        $fallback = (string) config('center-auth.client.fallback_url', '');

        if ($fallback !== '') {
            return $fallback;
        }

        $serverUrl = (string) config('center-auth.client.server_url', '');

        return $serverUrl !== '' ? $serverUrl : '/';
    }
}
