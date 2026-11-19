<?php

namespace CenterAuth\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;

class CodeGenerated
{
    use Dispatchable;

    public function __construct(
        public readonly string $clientId,
        public readonly Authenticatable $user,
        public readonly string $targetPage,
    ) {
    }
}
