<?php

namespace CenterAuth\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Http\Request;
use Throwable;

class AuthenticationFailed
{
    use Dispatchable;

    public function __construct(
        public readonly string $reason,
        public readonly Request $request,
        public readonly ?Throwable $exception = null,
    ) {
    }
}
