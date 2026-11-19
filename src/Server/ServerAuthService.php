<?php

namespace CenterAuth\Server;

use CenterAuth\CenterAuthManager;
use CenterAuth\Contracts\ClientRepository;
use CenterAuth\Data\ClientData;
use CenterAuth\Events\CodeExchanged;
use CenterAuth\Events\CodeGenerated;
use CenterAuth\Exceptions\CodeExchangeException;
use CenterAuth\Exceptions\InvalidClientException;
use CenterAuth\Exceptions\InvalidConfigurationException;
use CenterAuth\Support\KeyLoader;
use CenterAuth\Support\PathSanitizer;
use Firebase\JWT\JWT;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;

class ServerAuthService
{
    private const RESERVED_CLAIMS = ['iss', 'sub', 'aud', 'iat', 'nbf', 'exp', 'jti'];

    public function __construct(
        private readonly KeyLoader $keyLoader,
        private readonly CenterAuthManager $manager,
        private readonly ClientRepository $clients,
    ) {
    }

    /**
     * Issue a signed JWT, store it behind a single-use authorization code in cache,
     * and return the code.
     *
     * @param  array<string, mixed>  $extraClaims
     */
    public function issueCode(
        string $clientId,
        Authenticatable $user,
        string $targetPage = '/',
        array $extraClaims = [],
    ): string {
        $this->resolveActiveClient($clientId);

        $issuer = $this->getIssuer();
        $privateKey = $this->keyLoader->loadPrivateKey();
        $algorithm = (string) config('center-auth.keys.algorithm', 'RS256');
        $jwtTtl = max(5, (int) config('center-auth.server.jwt_ttl', 60));
        $codeTtl = max(5, (int) config('center-auth.server.code_ttl', 60));

        $sanitizedPage = PathSanitizer::sanitize($targetPage, '/');
        $now = time();

        $safeExtraClaims = array_diff_key($extraClaims, array_flip(self::RESERVED_CLAIMS));

        $payload = array_merge($safeExtraClaims, [
            'iss' => $issuer,
            'sub' => (string) $user->getAuthIdentifier(),
            'aud' => $clientId,
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + $jwtTtl,
            'jti' => (string) Str::uuid(),
            'page' => $sanitizedPage,
            'user' => $this->manager->resolveUserClaims($user, $clientId),
        ]);

        $jwt = JWT::encode($payload, $privateKey, $algorithm);
        $code = bin2hex(random_bytes(32));

        $this->cache()->put(
            $this->cacheKey($code),
            [
                'jwt' => $jwt,
                'client_id' => $clientId,
            ],
            $codeTtl
        );

        CodeGenerated::dispatch($clientId, $user, $sanitizedPage);

        return $code;
    }

    /**
     * Sign an arbitrary data array into a short-lived RS256 JWT (useful for
     * custom server-to-server APIs such as roles/permissions endpoints).
     *
     * @param  array<string, mixed>  $data
     */
    public function signPayload(array $data, ?string $audience = null, int $ttl = 60): string
    {
        $issuer = $this->getIssuer();
        $privateKey = $this->keyLoader->loadPrivateKey();
        $algorithm = (string) config('center-auth.keys.algorithm', 'RS256');
        $now = time();

        $payload = [
            'iss' => $issuer,
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + max(5, $ttl),
            'jti' => (string) Str::uuid(),
            'data' => $data,
        ];

        if ($audience !== null && trim($audience) !== '') {
            $payload['aud'] = trim($audience);
        }

        return JWT::encode($payload, $privateKey, $algorithm);
    }

    /**
     * Build the full callback URL for the given client and authorization code.
     */
    public function buildRedirectUrl(string $clientId, string $code): string
    {
        $client = $this->resolveActiveClient($clientId);
        $callbackUrl = $client->callbackUrl;
        $separator = str_contains($callbackUrl, '?') ? '&' : '?';

        return $callbackUrl . $separator . http_build_query(['code' => $code]);
    }

    /**
     * Issue a code and return a redirect response to the target client's callback URL.
     * Supports Inertia full-page redirects automatically when the request is an Inertia visit.
     *
     * @param  array<string, mixed>  $extraClaims
     */
    public function redirectToClient(
        string $clientId,
        Authenticatable $user,
        string $targetPage = '/',
        array $extraClaims = [],
        ?Request $request = null,
    ): Response {
        $code = $this->issueCode($clientId, $user, $targetPage, $extraClaims);
        $url = $this->buildRedirectUrl($clientId, $code);

        if ($request?->header('X-Inertia') && class_exists(\Inertia\Inertia::class)) {
            return \Inertia\Inertia::location($url);
        }

        return redirect()->away($url);
    }

    /**
     * Authenticate the client and atomically exchange a one-time authorization code for its signed JWT.
     */
    public function exchangeCode(string $code, string $clientId, string $clientSecret): string
    {
        $client = $this->resolveActiveClient($clientId);

        if (! $this->clients->verifySecret($client, $clientSecret)) {
            throw new InvalidClientException('Invalid client credentials.');
        }

        if (trim($code) === '') {
            throw new CodeExchangeException('Authorization code is required.');
        }

        $record = $this->cache()->pull($this->cacheKey($code));

        if (! is_array($record) || ! isset($record['jwt'], $record['client_id'])) {
            throw new CodeExchangeException('Authorization code is invalid or expired.');
        }

        if (! hash_equals((string) $record['client_id'], $clientId)) {
            throw new InvalidClientException('Authorization code was not issued for this client.');
        }

        $this->clients->touchLastUsed($clientId);

        CodeExchanged::dispatch($clientId);

        return (string) $record['jwt'];
    }

    private function resolveActiveClient(string $clientId): ClientData
    {
        $client = $this->clients->find($clientId);

        if ($client === null) {
            throw new InvalidClientException("Unknown CenterAuth client [{$clientId}].");
        }

        if (! $client->isActive) {
            throw new InvalidClientException("CenterAuth client [{$clientId}] is disabled.");
        }

        return $client;
    }

    private function getIssuer(): string
    {
        $issuer = rtrim((string) config('center-auth.server.issuer', ''), '/');

        if ($issuer === '') {
            throw new InvalidConfigurationException('CenterAuth server issuer (center-auth.server.issuer) is not configured.');
        }

        return $issuer;
    }

    private function cache(): CacheRepository
    {
        $store = config('center-auth.server.cache_store');

        return $store ? Cache::store((string) $store) : Cache::store();
    }

    private function cacheKey(string $code): string
    {
        $prefix = (string) config('center-auth.server.cache_prefix', 'center_auth_code_');

        return $prefix . hash('sha256', $code);
    }
}
