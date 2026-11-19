<?php

namespace CenterAuth\Data;

readonly class ClientData
{
    public function __construct(
        public string $clientId,
        public string $name,
        public string $callbackUrl,
        public bool $isActive = true,
        public ?string $secret = null,
        public ?string $description = null,
        public ?int $databaseId = null,
    ) {
    }
}
