<?php

namespace CenterAuth\Tests\Unit;

use CenterAuth\Support\PathSanitizer;
use PHPUnit\Framework\TestCase;

class PathSanitizerTest extends TestCase
{
    public function test_accepts_valid_relative_paths(): void
    {
        $this->assertSame('/dashboard', PathSanitizer::sanitize('/dashboard'));
        $this->assertSame('/tickets/42?status=open#top', PathSanitizer::sanitize('/tickets/42?status=open#top'));
        $this->assertSame('/dashboard', PathSanitizer::sanitize('dashboard'));
        $this->assertSame('/', PathSanitizer::sanitize('/'));
    }

    public function test_rejects_open_redirect_and_malicious_inputs(): void
    {
        $this->assertSame('/', PathSanitizer::sanitize('https://evil.com/phish'));
        $this->assertSame('/', PathSanitizer::sanitize('http://evil.com'));
        $this->assertSame('/', PathSanitizer::sanitize('//evil.com/phish'));
        $this->assertSame('/', PathSanitizer::sanitize('/\evil.com'));
        $this->assertSame('/', PathSanitizer::sanitize('javascript:alert(1)'));
        $this->assertSame('/', PathSanitizer::sanitize("/dashboard\r\nLocation: https://evil.com"));
        $this->assertSame('/', PathSanitizer::sanitize(''));
        $this->assertSame('/', PathSanitizer::sanitize(null));
        $this->assertSame('/home', PathSanitizer::sanitize('https://evil.com', '/home'));
    }
}
