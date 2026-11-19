<?php

namespace CenterAuth\Server\Http\Controllers;

use CenterAuth\Exceptions\CodeExchangeException;
use CenterAuth\Exceptions\InvalidClientException;
use CenterAuth\Server\ServerAuthService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;

class ExchangeController extends Controller
{
    public function __construct(
        private readonly ServerAuthService $serverAuth,
    ) {
    }

    public function __invoke(Request $request): JsonResponse
    {
        $clientId = (string) $request->header('X-Center-Auth-Client-Id', '');
        $clientSecret = (string) $request->header('X-Center-Auth-Client-Secret', '');
        $code = $request->input('code');

        if (! is_string($code) || trim($code) === '') {
            return response()->json([
                'message' => 'Authorization code is required.',
            ], 422);
        }

        try {
            $jwt = $this->serverAuth->exchangeCode($code, $clientId, $clientSecret);
        } catch (InvalidClientException $e) {
            return response()->json([
                'message' => $e->getMessage(),
            ], 401);
        } catch (CodeExchangeException $e) {
            return response()->json([
                'message' => $e->getMessage(),
            ], 400);
        }

        return response()->json([
            'jwt' => $jwt,
        ], 200, [
            'Cache-Control' => 'no-store, no-cache, must-revalidate',
            'Pragma' => 'no-cache',
        ]);
    }
}
