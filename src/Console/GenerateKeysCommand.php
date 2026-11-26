<?php

namespace CenterAuth\Console;

use Illuminate\Console\Command;

class GenerateKeysCommand extends Command
{
    protected $signature = 'center-auth:keys
                            {--force : Overwrite existing key files}
                            {--bits=2048 : RSA key size in bits (minimum 2048)}
                            {--private= : Custom path for the private key}
                            {--public= : Custom path for the public key}
                            {--openssl-config= : Optional path to openssl.cnf (useful on Windows)}';

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

        $explicitConfig = $this->option('openssl-config');
        if ($explicitConfig !== null && $explicitConfig !== '') {
            $explicitConfig = (string) $explicitConfig;
            if (! is_file($explicitConfig) || ! is_readable($explicitConfig)) {
                $this->components->error("OpenSSL config file not found or not readable: {$explicitConfig}");

                return self::FAILURE;
            }
        } else {
            $explicitConfig = null;
        }

        $generated = $this->generateKeypair($bits, $explicitConfig);

        if (! isset($generated['private'], $generated['public'])) {
            $this->components->error($generated['error'] ?? 'Failed to generate RSA keypair via OpenSSL.');

            foreach ($generated['openssl_errors'] ?? [] as $opensslError) {
                $this->line("  OpenSSL: {$opensslError}");
            }

            if ($explicitConfig === null) {
                $this->line('  Hint: On Windows, you can pass --openssl-config="C:\\path\\to\\openssl.cnf" or set the OPENSSL_CONF environment variable.');
            }

            return self::FAILURE;
        }

        $privateKey = $generated['private'];
        $publicKey = $generated['public'];

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

    /**
     * Generate and export an RSA keypair, falling back to auto-detected or minimal
     * OpenSSL configuration files when PHP cannot locate openssl.cnf (common on Windows).
     *
     * @return array{private?: string, public?: string, error?: string, openssl_errors?: list<string>}
     */
    private function generateKeypair(int $bits, ?string $explicitConfig): array
    {
        $baseOptions = [
            'private_key_bits' => $bits,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];

        if ($explicitConfig !== null) {
            return $this->attemptKeypairGeneration($baseOptions + ['config' => $explicitConfig]);
        }

        $result = $this->attemptKeypairGeneration($baseOptions);
        if (isset($result['private'], $result['public'])) {
            return $result;
        }

        foreach ($this->findSystemOpenSslConfigs() as $configPath) {
            $fallback = $this->attemptKeypairGeneration($baseOptions + ['config' => $configPath]);
            if (isset($fallback['private'], $fallback['public'])) {
                return $fallback;
            }
        }

        $tempConfig = $this->createTemporaryOpenSslConfig();
        if ($tempConfig !== null) {
            try {
                $fallback = $this->attemptKeypairGeneration($baseOptions + ['config' => $tempConfig]);
                if (isset($fallback['private'], $fallback['public'])) {
                    return $fallback;
                }
            } finally {
                @unlink($tempConfig);
            }
        }

        return $result;
    }

    /**
     * @param  array<string, mixed>  $options
     * @return array{private?: string, public?: string, error?: string, openssl_errors?: list<string>}
     */
    private function attemptKeypairGeneration(array $options): array
    {
        $this->drainOpenSslErrors();

        $resource = @openssl_pkey_new($options);
        if ($resource === false) {
            return [
                'error' => 'Failed to generate RSA keypair via OpenSSL.',
                'openssl_errors' => $this->drainOpenSslErrors(),
            ];
        }

        $privateKey = '';
        if (! @openssl_pkey_export($resource, $privateKey, null, $options)) {
            return [
                'error' => 'Failed to export private key.',
                'openssl_errors' => $this->drainOpenSslErrors(),
            ];
        }

        $details = @openssl_pkey_get_details($resource);
        if (! is_array($details) || empty($details['key'])) {
            return [
                'error' => 'Failed to extract public key.',
                'openssl_errors' => $this->drainOpenSslErrors(),
            ];
        }

        return [
            'private' => $privateKey,
            'public' => (string) $details['key'],
        ];
    }

    /**
     * @return list<string>
     */
    private function findSystemOpenSslConfigs(): array
    {
        $candidates = [];

        $envConfig = getenv('OPENSSL_CONF');
        if (is_string($envConfig) && $envConfig !== '') {
            $candidates[] = $envConfig;
        }

        $phpDir = dirname(PHP_BINARY);
        $sep = DIRECTORY_SEPARATOR;

        $candidates[] = $phpDir . $sep . 'extras' . $sep . 'ssl' . $sep . 'openssl.cnf';
        $candidates[] = $phpDir . $sep . 'openssl.cnf';
        $candidates[] = $phpDir . $sep . '..' . $sep . 'apache' . $sep . 'conf' . $sep . 'openssl.cnf';
        $candidates[] = $phpDir . $sep . '..' . $sep . 'etc' . $sep . 'ssl' . $sep . 'openssl.cnf';

        $valid = [];
        foreach (array_unique($candidates) as $path) {
            if (is_file($path) && is_readable($path)) {
                $valid[] = $path;
            }
        }

        return $valid;
    }

    private function createTemporaryOpenSslConfig(): ?string
    {
        $path = @tempnam(sys_get_temp_dir(), 'center_auth_openssl_');
        if ($path === false) {
            return null;
        }

        $contents = "HOME = .\n\n[req]\ndistinguished_name = req_distinguished_name\n\n[req_distinguished_name]\n";
        if (@file_put_contents($path, $contents) === false) {
            @unlink($path);

            return null;
        }

        return $path;
    }

    /**
     * @return list<string>
     */
    private function drainOpenSslErrors(): array
    {
        $errors = [];
        while (($error = openssl_error_string()) !== false) {
            $errors[] = $error;
        }

        return $errors;
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
