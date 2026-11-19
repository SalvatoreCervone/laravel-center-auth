<?php

namespace CenterAuth\Contracts;

use CenterAuth\Data\ClientData;

interface ClientRepository
{
    public function find(string $clientId): ?ClientData;

    /**
     * @return list<ClientData>
     */
    public function all(): array;

    public function verifySecret(ClientData $client, string $plainSecret): bool;

    public function touchLastUsed(string $clientId): void;
}
