<?php

namespace CenterAuth\Tests\Feature;

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
}
