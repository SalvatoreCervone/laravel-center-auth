<?php

namespace CenterAuth\Events;

use Illuminate\Foundation\Events\Dispatchable;

class CodeExchanged
{
    use Dispatchable;

    public function __construct(
        public readonly string $clientId,
    ) {
    }
}
