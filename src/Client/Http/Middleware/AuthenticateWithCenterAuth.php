<?php

namespace CenterAuth\Client\Http\Middleware;

use CenterAuth\Client\ClientAuthService;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class AuthenticateWithCenterAuth
{
    public function __construct(
        private readonly ClientAuthService $clientAuth,
    ) {
    }

    public function handle(Request $request, Closure $next, ?string $guard = null): Response
    {
        $resolvedGuard = ($guard !== null && $guard !== '')
            ? $guard
            : config('center-auth.client.guard');

        if (Auth::guard($resolvedGuard)->check()) {
            if (is_string($resolvedGuard) && $resolvedGuard !== '') {
                Auth::shouldUse($resolvedGuard);
            }

            return $next($request);
        }

        if ($request->expectsJson() && ! $request->header('X-Inertia')) {
            return response()->json(['message' => 'Unauthenticated.'], 401);
        }

        return $this->clientAuth->redirectToServer(request: $request);
    }
}
