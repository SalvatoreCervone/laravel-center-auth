<?php

namespace CenterAuth\Support;

class PathSanitizer
{
    /**
     * Sanitize a target redirect path so it is strictly a safe relative path
     * on the current host, preventing open-redirect and header-injection attacks.
     */
    public static function sanitize(?string $path, string $fallback = '/'): string
    {
        if ($path === null) {
            return $fallback;
        }

        $trimmed = trim($path);

        if ($trimmed === '') {
            return $fallback;
        }

        // Reject control characters (CR, LF, NUL, etc.) and backslashes
        if (preg_match('/[\x00-\x1F\x7F\\\\]/', $trimmed) === 1) {
            return $fallback;
        }

        // Reject protocol-relative URLs (e.g. //evil.com)
        if (str_starts_with($trimmed, '//')) {
            return $fallback;
        }

        // Reject any scheme or host (e.g. https://evil.com, javascript:alert(1))
        $parsed = parse_url($trimmed);

        if ($parsed === false || isset($parsed['scheme']) || isset($parsed['host'])) {
            return $fallback;
        }

        $normalized = str_starts_with($trimmed, '/') ? $trimmed : '/' . $trimmed;

        // Re-check after prefixing '/' in case input was '/evil.com' -> '//evil.com'
        if (str_starts_with($normalized, '//')) {
            return $fallback;
        }

        return $normalized;
    }
}
