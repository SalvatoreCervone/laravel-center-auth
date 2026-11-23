<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Operating Mode
    |--------------------------------------------------------------------------
    |
    | Determines which routes and services are registered by this package.
    | Supported values: "server", "client", "both".
    |
    */
    'mode' => env('CENTER_AUTH_MODE', 'client'),

    /*
    |--------------------------------------------------------------------------
    | Route Prefix
    |--------------------------------------------------------------------------
    |
    | URL prefix used for the server (/redirect/{client}, /exchange) and
    | client (/callback) endpoints.
    |
    */
    'route_prefix' => env('CENTER_AUTH_ROUTE_PREFIX', 'center-auth'),

    /*
    |--------------------------------------------------------------------------
    | Cryptographic Keys (RS256)
    |--------------------------------------------------------------------------
    |
    | The server requires the private key to sign JWTs.
    | The client requires only the public key to verify JWT signatures.
    | You can provide a file path or a raw PEM string via environment variables.
    |
    */
    'keys' => [
        'algorithm' => 'RS256',
        'private_key_path' => env('CENTER_AUTH_PRIVATE_KEY_PATH', storage_path('center-auth/private.key')),
        'public_key_path' => env('CENTER_AUTH_PUBLIC_KEY_PATH', storage_path('center-auth/public.key')),
        'private_key' => env('CENTER_AUTH_PRIVATE_KEY'),
        'public_key' => env('CENTER_AUTH_PUBLIC_KEY'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Server Configuration
    |--------------------------------------------------------------------------
    |
    | Used when mode is "server" or "both".
    |
    */
    'server' => [
        // Where registered client apps are stored: "config" or "database".
        'client_driver' => env('CENTER_AUTH_CLIENT_DRIVER', 'config'),

        // Issuer claim (iss) embedded into generated JWTs.
        'issuer' => env('CENTER_AUTH_ISSUER', env('APP_URL')),

        // Lifetime in seconds of the one-time authorization code stored in cache.
        'code_ttl' => (int) env('CENTER_AUTH_CODE_TTL', 60),

        // Lifetime in seconds of the signed JWT returned by /exchange.
        'jwt_ttl' => (int) env('CENTER_AUTH_JWT_TTL', 60),

        // Cache store used for one-time authorization codes (null = default store).
        'cache_store' => env('CENTER_AUTH_CACHE_STORE'),

        // Prefix for authorization code cache keys.
        'cache_prefix' => 'center_auth_code_',

        // Middleware applied to server routes.
        'redirect_middleware' => ['web', 'auth'],
        'exchange_middleware' => ['throttle:60,1'],

        // Built-in admin panel to manage connected client applications (requires client_driver = database).
        'panel' => [
            'enabled' => filter_var(env('CENTER_AUTH_PANEL_ENABLED', false), FILTER_VALIDATE_BOOLEAN),
            'prefix' => env('CENTER_AUTH_PANEL_PREFIX', 'center-auth/admin'),
            'middleware' => ['web', 'auth'],
            'gate' => env('CENTER_AUTH_PANEL_GATE'),
            'secret_rotation_grace_hours' => (int) env('CENTER_AUTH_SECRET_GRACE_HOURS', 24),
        ],

        /*
        | Registered client applications.
        |
        | Example:
        | 'clients' => [
        |     'app-alpha' => [
        |         'secret' => env('CENTER_AUTH_CLIENT_ALPHA_SECRET'),
        |         'callback_url' => env('CENTER_AUTH_CLIENT_ALPHA_CALLBACK'),
        |     ],
        |     'app-beta' => [
        |         'secret' => env('CENTER_AUTH_CLIENT_BETA_SECRET'),
        |         'callback_url' => env('CENTER_AUTH_CLIENT_BETA_CALLBACK'),
        |     ],
        | ],
        */
        'clients' => [],
    ],

    /*
    |--------------------------------------------------------------------------
    | Client Configuration
    |--------------------------------------------------------------------------
    |
    | Used when mode is "client" or "both".
    |
    */
    'client' => [
        // Identifier and shared secret assigned to this app on the auth server.
        'client_id' => env('CENTER_AUTH_CLIENT_ID'),
        'client_secret' => env('CENTER_AUTH_CLIENT_SECRET'),

        // Public URL of the central auth server (used to verify "iss" and as fallback).
        'server_url' => env('CENTER_AUTH_SERVER_URL'),

        // Optional internal URL for back-channel POST /exchange calls (defaults to server_url).
        'server_api_url' => env('CENTER_AUTH_SERVER_API_URL', env('CENTER_AUTH_SERVER_URL')),

        // HTTP client options for the back-channel /exchange request.
        'verify_ssl' => filter_var(env('CENTER_AUTH_VERIFY_SSL', true), FILTER_VALIDATE_BOOLEAN),
        'http_timeout' => (int) env('CENTER_AUTH_HTTP_TIMEOUT', 10),
        'http_proxy' => env('CENTER_AUTH_HTTP_PROXY'),

        // Clock skew tolerance in seconds when verifying JWT nbf/iat/exp claims.
        'jwt_leeway' => (int) env('CENTER_AUTH_JWT_LEEWAY', 5),

        // Default relative path to redirect to after successful login.
        'default_redirect' => env('CENTER_AUTH_DEFAULT_REDIRECT', '/'),

        // Trusted URL to redirect to when authentication fails (never taken from query string).
        'fallback_url' => env('CENTER_AUTH_FALLBACK_URL', env('CENTER_AUTH_SERVER_URL', '/')),

        // Eloquent model used for local user synchronization.
        'user_model' => env('CENTER_AUTH_USER_MODEL', 'App\\Models\\User'),

        // Laravel auth guard used to log the user in (null = default guard).
        'guard' => env('CENTER_AUTH_GUARD'),

        // Middleware applied to the client /callback route.
        'callback_middleware' => ['web'],
    ],

];
