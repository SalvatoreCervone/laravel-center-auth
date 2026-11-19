<?php

namespace CenterAuth\Server\Repositories;

use CenterAuth\Contracts\ClientRepository;
use CenterAuth\Data\ClientData;
use CenterAuth\Exceptions\InvalidConfigurationException;
use CenterAuth\Models\CenterAuthClient;

class DatabaseClientRepository implements ClientRepository
{
    public function find(string $clientId): ?ClientData
    {
        $model = CenterAuthClient::query()->where('client_id', $clientId)->first();

        if ($model === null) {
            return null;
        }

        return $this->hydrate($model);
    }

    public function all(): array
    {
        return CenterAuthClient::query()
            ->orderBy('name')
            ->get()
            ->map(fn (CenterAuthClient $model) => $this->hydrate($model))
            ->all();
    }

    public function verifySecret(ClientData $client, string $plainSecret): bool
    {
        if ($plainSecret === '') {
            return false;
        }

        $model = $client->databaseId !== null
            ? CenterAuthClient::query()->find($client->databaseId)
            : CenterAuthClient::query()->where('client_id', $client->clientId)->first();

        if ($model === null) {
            return false;
        }

        return $model->verifySecret($plainSecret);
    }

    public function touchLastUsed(string $clientId): void
    {
        CenterAuthClient::query()
            ->where('client_id', $clientId)
            ->update(['last_used_at' => now()]);
    }

    private function hydrate(CenterAuthClient $model): ClientData
    {
        if (! preg_match('#^https?://#i', $model->callback_url)) {
            throw new InvalidConfigurationException("CenterAuth client [{$model->client_id}] has an invalid callback_url.");
        }

        return new ClientData(
            clientId: $model->client_id,
            name: $model->name,
            callbackUrl: $model->callback_url,
            isActive: (bool) $model->is_active,
            secret: null,
            description: $model->description,
            databaseId: $model->id,
        );
    }
}
