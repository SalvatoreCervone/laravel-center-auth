<?php

namespace CenterAuth\Facades;

use CenterAuth\CenterAuthManager;
use CenterAuth\Client\ClientAuthService;
use CenterAuth\Server\ServerAuthService;
use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Facade;
use Symfony\Component\HttpFoundation\Response;

/**
 * @method static ServerAuthService server()
 * @method static ClientAuthService client()
 * @method static Response redirectToClient(string $clientId, Authenticatable $user, string $targetPage = '/', array $extraClaims = [], ?Request $request = null)
 * @method static Response redirectToServer(?string $targetPage = null, ?Request $request = null)
 * @method static void resolveUserClaimsUsing(Closure $callback)
 * @method static void resolveUserUsing(Closure $callback)
 * @method static void beforeLoginUsing(Closure $callback)
 * @method static void authorizePanelUsing(Closure $callback)
 * @method static void resetHooks()
 *
 * @see \CenterAuth\CenterAuthManager
 */
class CenterAuth extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return CenterAuthManager::class;
    }
}
