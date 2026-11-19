<?php

namespace CenterAuth\Server\Http\Controllers;

use CenterAuth\Exceptions\InvalidClientException;
use CenterAuth\Server\ServerAuthService;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Symfony\Component\HttpFoundation\Response;

class RedirectController extends Controller
{
    public function __construct(
        private readonly ServerAuthService $serverAuth,
    ) {
    }

    public function __invoke(Request $request, string $client): Response
    {
        $user = $request->user();

        if ($user === null) {
            abort(401, 'Unauthenticated.');
        }

        $targetPage = (string) $request->query('page', '/');

        try {
            return $this->serverAuth->redirectToClient(
                clientId: $client,
                user: $user,
                targetPage: $targetPage,
                request: $request,
            );
        } catch (InvalidClientException $e) {
            abort(404, $e->getMessage());
        }
    }
}
