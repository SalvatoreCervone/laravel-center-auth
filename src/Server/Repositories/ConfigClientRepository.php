<?php

namespace CenterAuth\Server\Repositories;

use CenterAuth\Contracts\ClientRepository;
use CenterAuth\Data\ClientData;
use CenterAuth\Exceptions\InvalidConfigurationException;

class ConfigClientRepository implements ClientRepository
{
    public function find(string $clientId): ?ClientData
    {
        $clients = config('center-auth.server.clients', []);

        if (! is_array($clients) || ! isset($clients[$clientId]) || ! is_array($clients[$clientId])) {
            return null;
        }

        return $this->hydrate($clientId, $clients[$clientId]);
    }

    public function all(): array
    {
        $clients = config('center-auth.server.clients', []);

        if (! is_array($clients)) {
            return [];
        }

        $result = [];
        foreach ($clients as $clientId => $data) {
            if (is_string($clientId) && is_array($data)) {
                $result[] = $this->hydrate($clientId, $data);
            }
        }

        return $result;
    }

    public function verifySecret(ClientData $client, string $plainSecret): bool
    {
        if ($plainSecret === '' || $client->secret === null || $client->secret === '') {
            return false;
        }

        return hash_equals($client->secret, $plainSecret);
    }

    public function touchLastUsed(string $clientId): void
    {
        // No-op for static config driver.
    }

    /**
     * @param  array<string, mixed>  $data
     */
    private function hydrate(string $clientId, array $data): ClientData
    {
        $secret = (string) ($data['secret'] ?? '');
        $callbackUrl = (string) ($data['callback_url'] ?? '');

        if ($secret === '') {
            throw new InvalidConfigurationException("CenterAuth client [{$clientId}] has no secret configured.");
        }

        if ($callbackUrl === '' || ! preg_match('#^https?://#i', $callbackUrl)) {
            throw new InvalidConfigurationException("CenterAuth client [{$clientId}] has an invalid callback_url.");
        }

        return new ClientData(
            clientId: $clientId,
            name: (string) ($data['name'] ?? $clientId),
            callbackUrl: $callbackUrl,
            isActive: (bool) ($data['is_active'] ?? true),
            secret: $secret,
            description: isset($data['description']) ? (string) $data['description'] : null,
        );
    }
}
