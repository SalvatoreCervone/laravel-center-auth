<?php

namespace CenterAuth\Data;

readonly class AuthPayload
{
    /**
     * @param  array<string, mixed>  $userData
     * @param  array<string, mixed>  $claims
     */
    public function __construct(
        public string $sub,
        public string $email,
        public string $name,
        public string $page,
        public string $issuer,
        public string $audience,
        public string $jti,
        public int $issuedAt,
        public int $expiresAt,
        public array $userData = [],
        public array $claims = [],
    ) {
    }

    /**
     * Retrieve a custom claim from the decoded JWT payload.
     */
    public function claim(string $key, mixed $default = null): mixed
    {
        return $this->claims[$key] ?? $default;
    }
}
