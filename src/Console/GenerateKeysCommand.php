<?php

namespace CenterAuth\Console;

use Illuminate\Console\Command;

class GenerateKeysCommand extends Command
{
    protected $signature = 'center-auth:keys
                            {--force : Overwrite existing key files}
                            {--bits=2048 : RSA key size in bits (minimum 2048)}
                            {--private= : Custom path for the private key}
                            {--public= : Custom path for the public key}';

    protected $description = 'Generate an RSA keypair (RS256) for CenterAuth server signing and client verification';

    public function handle(): int
    {
        $bits = (int) $this->option('bits');
        if ($bits < 2048) {
            $this->components->error('Key size must be at least 2048 bits.');

            return self::FAILURE;
        }

        $privatePath = (string) ($this->option('private') ?: config('center-auth.keys.private_key_path'));
        $publicPath = (string) ($this->option('public') ?: config('center-auth.keys.public_key_path'));

        if (! $this->option('force') && (file_exists($privatePath) || file_exists($publicPath))) {
            $this->components->error('Key files already exist. Use --force to overwrite them.');

            return self::FAILURE;
        }

        $resource = openssl_pkey_new([
            'private_key_bits' => $bits,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($resource === false) {
            $this->components->error('Failed to generate RSA keypair via OpenSSL.');

            return self::FAILURE;
        }

        $privateKey = '';
        if (! openssl_pkey_export($resource, $privateKey)) {
            $this->components->error('Failed to export private key.');

            return self::FAILURE;
        }

        $details = openssl_pkey_get_details($resource);
        if (! is_array($details) || empty($details['key'])) {
            $this->components->error('Failed to extract public key.');

            return self::FAILURE;
        }

        $publicKey = (string) $details['key'];

        if (! $this->ensureDirectoryExists(dirname($privatePath))) {
            $this->components->error('Failed to create directory for private key: ' . dirname($privatePath));

            return self::FAILURE;
        }

        if (! $this->ensureDirectoryExists(dirname($publicPath))) {
            $this->components->error('Failed to create directory for public key: ' . dirname($publicPath));

            return self::FAILURE;
        }

        $oldUmask = umask(0077);
        try {
            $written = @file_put_contents($privatePath, $privateKey);
        } finally {
            umask($oldUmask);
        }

        if ($written === false) {
            $this->components->error("Failed to write private key to {$privatePath}.");

            return self::FAILURE;
        }

        @chmod($privatePath, 0600);

        if (@file_put_contents($publicPath, $publicKey) === false) {
            $this->components->error("Failed to write public key to {$publicPath}.");

            return self::FAILURE;
        }

        @chmod($publicPath, 0644);

        $this->components->info('CenterAuth RSA keypair generated successfully.');
        $this->line("  Private key (SERVER only): {$privatePath}");
        $this->line("  Public key  (CLIENTS):     {$publicPath}");

        return self::SUCCESS;
    }

    private function ensureDirectoryExists(string $directory): bool
    {
        if (is_dir($directory)) {
            return true;
        }

        @mkdir($directory, 0755, true);

        return is_dir($directory);
    }
}
