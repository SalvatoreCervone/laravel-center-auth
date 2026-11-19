<?php

namespace CenterAuth\Tests\Unit;

use CenterAuth\Exceptions\InvalidConfigurationException;
use CenterAuth\Support\KeyLoader;
use CenterAuth\Tests\TestCase;

class KeyLoaderTest extends TestCase
{
    public function test_loads_raw_keys_and_unescapes_newlines(): void
    {
        $escaped = str_replace("\n", '\n', self::$testPublicKey);
        config()->set('center-auth.keys.public_key', $escaped);

        $loader = new KeyLoader();

        $this->assertSame(trim(self::$testPublicKey), $loader->loadPublicKey());
    }

    public function test_loads_key_from_file_when_raw_key_is_null(): void
    {
        $tmpFile = sys_get_temp_dir() . '/center_auth_test_pub_' . uniqid() . '.key';
        file_put_contents($tmpFile, self::$testPublicKey);

        try {
            config()->set('center-auth.keys.public_key', null);
            config()->set('center-auth.keys.public_key_path', $tmpFile);

            $loader = new KeyLoader();
            $this->assertSame(self::$testPublicKey, $loader->loadPublicKey());
        } finally {
            @unlink($tmpFile);
        }
    }

    public function test_throws_when_key_file_is_missing(): void
    {
        config()->set('center-auth.keys.private_key', null);
        config()->set('center-auth.keys.private_key_path', '/nonexistent/path/private.key');

        $this->expectException(InvalidConfigurationException::class);

        (new KeyLoader())->loadPrivateKey();
    }
}
