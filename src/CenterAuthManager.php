<?php

namespace CenterAuth;

use CenterAuth\Client\ClientAuthService;
use CenterAuth\Data\AuthPayload;
use CenterAuth\Server\ServerAuthService;
use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Symfony\Component\HttpFoundation\Response;

class CenterAuthManager
{
    private ?Closure $userClaimsResolver = null;

    private ?Closure $userResolver = null;

    private ?Closure $beforeLoginHook = null;

    private ?Closure $panelAuthorizer = null;

    public function __construct(
        private readonly Container $app,
    ) {
    }

    public function server(): ServerAuthService
    {
        return $this->app->make(ServerAuthService::class);
    }

    public function client(): ClientAuthService
    {
        return $this->app->make(ClientAuthService::class);
    }

    /**
     * Convenience helper on the server side to issue a one-time code and
     * redirect the authenticated user to a registered client application.
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
        return $this->server()->redirectToClient($clientId, $user, $targetPage, $extraClaims, $request);
    }

    /**
     * Convenience helper on the client side to redirect an unauthenticated user
     * to the central auth server while preserving the requested target page.
     */
    public function redirectToServer(?string $targetPage = null, ?Request $request = null): Response
    {
        return $this->client()->redirectToServer($targetPage, $request);
    }

    /**
     * Customize the user claims embedded in the server-issued JWT.
     * Signature: fn(Authenticatable $user, string $clientId): array
     */
    public function resolveUserClaimsUsing(Closure $callback): void
    {
        $this->userClaimsResolver = $callback;
    }

    /**
     * @return array<string, mixed>
     */
    public function resolveUserClaims(Authenticatable $user, string $clientId): array
    {
        if ($this->userClaimsResolver !== null) {
            return ($this->userClaimsResolver)($user, $clientId);
        }

        return [
            'id' => $user->getAuthIdentifier(),
            'name' => (string) ($user->name ?? ''),
            'email' => (string) ($user->email ?? ''),
        ];
    }

    /**
     * Customize how the client application resolves or creates the local user from the verified JWT payload.
     * Signature: fn(AuthPayload $payload): Authenticatable
     */
    public function resolveUserUsing(Closure $callback): void
    {
        $this->userResolver = $callback;
    }

    public function getUserResolver(): ?Closure
    {
        return $this->userResolver;
    }

    /**
     * Register a hook invoked on the client right before logging the user in.
     * Returning false denies login (ideal for custom authorization / permission checks).
     * Signature: fn(Authenticatable $user, AuthPayload $payload, Request $request): bool
     */
    public function beforeLoginUsing(Closure $callback): void
    {
        $this->beforeLoginHook = $callback;
    }

    public function runBeforeLogin(Authenticatable $user, AuthPayload $payload, Request $request): bool
    {
        if ($this->beforeLoginHook === null) {
            return true;
        }

        return (bool) ($this->beforeLoginHook)($user, $payload, $request);
    }

    /**
     * Authorize access to the built-in server admin panel.
     * Signature: fn(Request $request): bool
     */
    public function authorizePanelUsing(Closure $callback): void
    {
        $this->panelAuthorizer = $callback;
    }

    public function canAccessPanel(Request $request): bool
    {
        if ($this->panelAuthorizer !== null) {
            return (bool) ($this->panelAuthorizer)($request);
        }

        $gate = config('center-auth.server.panel.gate');
        if (is_string($gate) && trim($gate) !== '') {
            return Gate::forUser($request->user())->allows(trim($gate));
        }

        return method_exists($this->app, 'environment') && (bool) $this->app->environment('local');
    }

    /**
     * Clear all registered runtime hooks (primarily useful in tests).
     */
    public function resetHooks(): void
    {
        $this->userClaimsResolver = null;
        $this->userResolver = null;
        $this->beforeLoginHook = null;
        $this->panelAuthorizer = null;
    }
}
