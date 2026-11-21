<?php

namespace CenterAuth\Client;

use CenterAuth\Data\AuthPayload;
use CenterAuth\Exceptions\InvalidConfigurationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Hash;

class UserSynchronizer
{
    /**
     * Find or create the local user matching the verified JWT payload.
     * Only whitelisted attributes are written; password is set to a random
     * value only on initial creation and never overwritten on subsequent logins.
     */
    public function sync(AuthPayload $payload): Authenticatable
    {
        $modelClass = (string) config('center-auth.client.user_model', 'App\\Models\\User');

        if (! class_exists($modelClass) || ! is_subclass_of($modelClass, Model::class)) {
            throw new InvalidConfigurationException(
                "Configured CenterAuth user model [{$modelClass}] does not exist or is not an Eloquent model."
            );
        }

        /** @var Model&Authenticatable|null $user */
        $user = $modelClass::query()->where('email', $payload->email)->first();

        if ($user === null) {
            /** @var Model&Authenticatable $user */
            $user = new $modelClass();
            $user->forceFill([
                'email' => $payload->email,
                'name' => $payload->name !== '' ? $payload->name : $payload->email,
                'password' => Hash::make(bin2hex(random_bytes(20))),
            ]);
            try {
                $user->save();
            } catch (QueryException $e) {
                /** @var Model&Authenticatable|null $existing */
                $existing = $modelClass::query()->where('email', $payload->email)->first();

                if ($existing !== null) {
                    return $existing;
                }

                throw $e;
            }

            return $user;
        }

        if ($payload->name !== '' && $user->getAttribute('name') !== $payload->name) {
            $user->forceFill(['name' => $payload->name]);
            $user->save();
        }

        return $user;
    }
}
