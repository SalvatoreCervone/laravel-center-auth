<?php

namespace CenterAuth\Tests;

use CenterAuth\CenterAuthServiceProvider;
use CenterAuth\Facades\CenterAuth;
use CenterAuth\Tests\Fixtures\User;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase as OrchestraTestCase;

abstract class TestCase extends OrchestraTestCase
{
    protected static ?string $testPrivateKey = null;

    protected static ?string $testPublicKey = null;

    protected function setUp(): void
    {
        $this->ensureTestKeyPair();

        parent::setUp();

        $this->setUpDatabase();
    }

    protected function tearDown(): void
    {
        CenterAuth::resetHooks();

        parent::tearDown();
    }

    protected function getPackageProviders($app): array
    {
        return [
            CenterAuthServiceProvider::class,
        ];
    }

    protected function getPackageAliases($app): array
    {
        return [
            'CenterAuth' => CenterAuth::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        $this->ensureTestKeyPair();

        $app['config']->set('app.key', 'base64:' . base64_encode(random_bytes(32)));
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
        $app['config']->set('auth.providers.users.model', User::class);

        $app['config']->set('center-auth.mode', 'both');
        $app['config']->set('center-auth.route_prefix', 'center-auth');
        $app['config']->set('center-auth.keys.private_key', self::$testPrivateKey);
        $app['config']->set('center-auth.keys.public_key', self::$testPublicKey);

        $app['config']->set('center-auth.server.issuer', 'https://auth.test');
        $app['config']->set('center-auth.server.code_ttl', 60);
        $app['config']->set('center-auth.server.jwt_ttl', 60);
        $app['config']->set('center-auth.server.clients', [
            'app-alpha' => [
                'secret' => 'alpha-secret-123',
                'callback_url' => 'https://alpha.test/center-auth/callback',
            ],
            'app-beta' => [
                'secret' => 'beta-secret-456',
                'callback_url' => 'https://beta.test/center-auth/callback',
            ],
        ]);

        $app['config']->set('center-auth.client.client_id', 'app-alpha');
        $app['config']->set('center-auth.client.client_secret', 'alpha-secret-123');
        $app['config']->set('center-auth.client.server_url', 'https://auth.test');
        $app['config']->set('center-auth.client.server_api_url', 'https://auth.test');
        $app['config']->set('center-auth.client.fallback_url', 'https://auth.test/login');
        $app['config']->set('center-auth.client.default_redirect', '/');
        $app['config']->set('center-auth.client.user_model', User::class);
        $app['config']->set('center-auth.client.verify_ssl', true);
    }

    protected function setUpDatabase(): void
    {
        Schema::create('users', function (Blueprint $table): void {
            $table->id();
            $table->string('name');
            $table->string('email')->unique();
            $table->string('password');
            $table->rememberToken();
            $table->timestamps();
        });
    }

    private function ensureTestKeyPair(): void
    {
        if (self::$testPrivateKey !== null && self::$testPublicKey !== null) {
            return;
        }

        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        openssl_pkey_export($resource, $privateKey);
        $details = openssl_pkey_get_details($resource);

        self::$testPrivateKey = $privateKey;
        self::$testPublicKey = $details['key'];
    }
}
