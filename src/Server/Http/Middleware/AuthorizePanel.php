<?php

namespace CenterAuth\Server\Http\Middleware;

use CenterAuth\CenterAuthManager;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class AuthorizePanel
{
    public function __construct(
        private readonly CenterAuthManager $manager,
    ) {
    }

    public function handle(Request $request, Closure $next): Response
    {
        if (! $this->manager->canAccessPanel($request)) {
            abort(403, 'You are not authorized to access the CenterAuth panel.');
        }

        return $next($request);
    }
}
