<?php

namespace CenterAuth\Support;

use CenterAuth\Exceptions\InvalidConfigurationException;

class KeyLoader
{
    public function loadPrivateKey(): string
    {
        return $this->loadKey(
            rawKey: config('center-auth.keys.private_key'),
            path: config('center-auth.keys.private_key_path'),
            label: 'private',
        );
    }

    public function loadPublicKey(): string
    {
        return $this->loadKey(
            rawKey: config('center-auth.keys.public_key'),
            path: config('center-auth.keys.public_key_path'),
            label: 'public',
        );
    }

    private function loadKey(?string $rawKey, ?string $path, string $label): string
    {
        if (is_string($rawKey) && trim($rawKey) !== '') {
            return trim(str_replace('\n', "\n", $rawKey));
        }

        if (! is_string($path) || trim($path) === '') {
            throw new InvalidConfigurationException(
                "CenterAuth {$label} key is not configured. Set center-auth.keys.{$label}_key or {$label}_key_path."
            );
        }

        if (! is_file($path) || ! is_readable($path)) {
            throw new InvalidConfigurationException(
                "CenterAuth {$label} key file not found or not readable at [{$path}]."
            );
        }

        $contents = file_get_contents($path);

        if ($contents === false || trim($contents) === '') {
            throw new InvalidConfigurationException(
                "CenterAuth {$label} key file at [{$path}] is empty or could not be read."
            );
        }

        return $contents;
    }
}
