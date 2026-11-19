<?php

namespace CenterAuth\Client\Http\Controllers;

use CenterAuth\Client\ClientAuthService;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;

class CallbackController extends Controller
{
    public function __construct(
        private readonly ClientAuthService $clientAuth,
    ) {
    }

    public function __invoke(Request $request): RedirectResponse
    {
        return $this->clientAuth->handleCallback($request);
    }
}
