<?php

namespace CenterAuth\Tests\Feature;

use CenterAuth\Tests\TestCase;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class GenerateKeysCommandTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        parent::setUp();

        $this->tempDir = sys_get_temp_dir() . '/center_auth_keys_' . uniqid();
    }

    protected function tearDown(): void
    {
        @unlink($this->tempDir . '/private.key');
        @unlink($this->tempDir . '/public.key');
        @unlink($this->tempDir . '/openssl.cnf');
        @rmdir($this->tempDir);

        parent::tearDown();
    }

    public function test_generates_valid_rsa_keypair_and_respects_force_flag(): void
    {
        $privatePath = $this->tempDir . '/private.key';
        $publicPath = $this->tempDir . '/public.key';

        $this->artisan('center-auth:keys', [
            '--private' => $privatePath,
            '--public' => $publicPath,
        ])->assertSuccessful();

        $this->assertFileExists($privatePath);
        $this->assertFileExists($publicPath);
        clearstatcache(true, $privatePath);
        $this->assertSame('0600', substr(sprintf('%o', fileperms($privatePath)), -4));

        // Verify generated keypair works with RS256 JWT signing & verification
        $privateKey = file_get_contents($privatePath);
        $publicKey = file_get_contents($publicPath);
        $token = JWT::encode(['sub' => '42'], $privateKey, 'RS256');
        $decoded = JWT::decode($token, new Key($publicKey, 'RS256'));
        $this->assertSame('42', $decoded->sub);

        // Without --force it must refuse to overwrite
        $this->artisan('center-auth:keys', [
            '--private' => $privatePath,
            '--public' => $publicPath,
        ])->assertFailed();

        // With --force it succeeds and enforces 0600 even on an existing looser file
        chmod($privatePath, 0644);
        $this->artisan('center-auth:keys', [
            '--private' => $privatePath,
            '--public' => $publicPath,
            '--force' => true,
        ])->assertSuccessful();

        clearstatcache(true, $privatePath);
        $this->assertSame('0600', substr(sprintf('%o', fileperms($privatePath)), -4));
    }

    public function test_rejects_key_size_smaller_than_2048_bits(): void
    {
        $this->artisan('center-auth:keys', [
            '--bits' => 1024,
            '--private' => $this->tempDir . '/private.key',
            '--public' => $this->tempDir . '/public.key',
        ])->assertFailed();
    }

    public function test_fails_cleanly_when_target_path_is_not_writable(): void
    {
        mkdir($this->tempDir, 0755, true);

        $this->artisan('center-auth:keys', [
            '--private' => $this->tempDir,
            '--public' => $this->tempDir . '/public.key',
            '--force' => true,
        ])->assertFailed();
    }

    public function test_generates_keypair_using_explicit_openssl_config(): void
    {
        mkdir($this->tempDir, 0755, true);
        $opensslConfig = $this->tempDir . '/openssl.cnf';
        file_put_contents(
            $opensslConfig,
            "HOME = .\n\n[req]\ndistinguished_name = req_distinguished_name\n\n[req_distinguished_name]\n"
        );

        $privatePath = $this->tempDir . '/private.key';
        $publicPath = $this->tempDir . '/public.key';

        $this->artisan('center-auth:keys', [
            '--private' => $privatePath,
            '--public' => $publicPath,
            '--openssl-config' => $opensslConfig,
        ])->assertSuccessful();

        $this->assertFileExists($privatePath);
        $this->assertFileExists($publicPath);
    }

    public function test_fails_when_explicit_openssl_config_does_not_exist(): void
    {
        $this->artisan('center-auth:keys', [
            '--private' => $this->tempDir . '/private.key',
            '--public' => $this->tempDir . '/public.key',
            '--openssl-config' => $this->tempDir . '/missing-openssl.cnf',
        ])->assertFailed();
    }
}
