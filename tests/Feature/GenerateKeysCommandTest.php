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

        // With --force it succeeds
        $this->artisan('center-auth:keys', [
            '--private' => $privatePath,
            '--public' => $publicPath,
            '--force' => true,
        ])->assertSuccessful();
    }

    public function test_rejects_key_size_smaller_than_2048_bits(): void
    {
        $this->artisan('center-auth:keys', [
            '--bits' => 1024,
            '--private' => $this->tempDir . '/private.key',
            '--public' => $this->tempDir . '/public.key',
        ])->assertFailed();
    }
}
