<?php

namespace CenterAuth\Tests\Feature;

use CenterAuth\Exceptions\InvalidConfigurationException;
use CenterAuth\Exceptions\InvalidTokenException;
use CenterAuth\Facades\CenterAuth;
use CenterAuth\Tests\TestCase;
use Firebase\JWT\JWT;

class SignedPayloadTest extends TestCase
{
    public function test_server_can_sign_payload_and_client_can_decode_and_verify_it(): void
    {
        $jwt = CenterAuth::server()->signPayload([
            'roles' => ['admin', 'editor'],
            'permissions' => ['tickets.view', 'tickets.create'],
        ], audience: 'app-alpha', ttl: 60);

        $decoded = CenterAuth::client()->decodePayload($jwt, requireAudience: true);

        $this->assertSame(['admin', 'editor'], $decoded['roles']);
        $this->assertSame(['tickets.view', 'tickets.create'], $decoded['permissions']);
    }

    public function test_decode_payload_rejects_wrong_audience(): void
    {
        $jwt = CenterAuth::server()->signPayload([
            'roles' => ['admin'],
        ], audience: 'app-beta');

        $this->expectException(InvalidTokenException::class);

        CenterAuth::client()->decodePayload($jwt);
    }

    public function test_decode_payload_rejects_missing_audience_when_required(): void
    {
        $jwt = CenterAuth::server()->signPayload([
            'roles' => ['admin'],
        ]);

        // Without requireAudience it succeeds
        $decoded = CenterAuth::client()->decodePayload($jwt);
        $this->assertSame(['admin'], $decoded['roles']);

        // With requireAudience=true it rejects
        $this->expectException(InvalidTokenException::class);
        CenterAuth::client()->decodePayload($jwt, requireAudience: true);
    }

    public function test_decode_payload_rejects_expired_token(): void
    {
        $jwt = JWT::encode([
            'iss' => 'https://auth.test',
            'aud' => 'app-alpha',
            'iat' => time() - 120,
            'exp' => time() - 10,
            'data' => ['roles' => ['admin']],
        ], self::$testPrivateKey, 'RS256');

        $this->expectException(InvalidTokenException::class);

        CenterAuth::client()->decodePayload($jwt);
    }

    public function test_decode_payload_rejects_wrong_issuer(): void
    {
        $jwt = JWT::encode([
            'iss' => 'https://evil.test',
            'aud' => 'app-alpha',
            'iat' => time(),
            'exp' => time() + 60,
            'data' => ['roles' => ['admin']],
        ], self::$testPrivateKey, 'RS256');

        $this->expectException(InvalidTokenException::class);

        CenterAuth::client()->decodePayload($jwt);
    }

    public function test_decode_payload_throws_when_server_url_is_empty(): void
    {
        $jwt = CenterAuth::server()->signPayload([
            'roles' => ['admin'],
        ], audience: 'app-alpha');

        config()->set('center-auth.client.server_url', '');

        $this->expectException(InvalidConfigurationException::class);

        CenterAuth::client()->decodePayload($jwt);
    }

    public function test_decode_payload_rejects_sso_login_jwt_without_data_claim(): void
    {
        $ssoJwt = JWT::encode([
            'iss' => 'https://auth.test',
            'sub' => '1',
            'aud' => 'app-alpha',
            'iat' => time(),
            'exp' => time() + 60,
            'jti' => 'jti-sso',
            'page' => '/dashboard',
            'user' => ['id' => 1, 'name' => 'Mario', 'email' => 'mario@example.com'],
        ], self::$testPrivateKey, 'RS256');

        $this->expectException(InvalidTokenException::class);

        CenterAuth::client()->decodePayload($ssoJwt);
    }

    public function test_decode_payload_rejects_jwt_with_both_data_and_user_claims(): void
    {
        $hybridJwt = JWT::encode([
            'iss' => 'https://auth.test',
            'sub' => '1',
            'aud' => 'app-alpha',
            'iat' => time(),
            'exp' => time() + 60,
            'jti' => 'jti-hybrid',
            'page' => '/dashboard',
            'user' => ['id' => 1, 'name' => 'Mario', 'email' => 'mario@example.com'],
            'data' => ['roles' => ['admin']],
        ], self::$testPrivateKey, 'RS256');

        $this->expectException(InvalidTokenException::class);

        CenterAuth::client()->decodePayload($hybridJwt);
    }
}
