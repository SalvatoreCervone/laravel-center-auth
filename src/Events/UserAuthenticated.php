<?php

namespace CenterAuth\Events;

use CenterAuth\Data\AuthPayload;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Http\Request;

class UserAuthenticated
{
    use Dispatchable;

    public function __construct(
        public readonly Authenticatable $user,
        public readonly AuthPayload $payload,
        public readonly Request $request,
    ) {
    }
}
