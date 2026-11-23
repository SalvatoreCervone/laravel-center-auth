# Laravel Center Auth

Componente Laravel leggero per autenticazione SSO in stile OAuth2 (**Authorization Code + JWT firmato RS256**), senza dover installare Laravel Passport.

Un unico package configurabile in modalità **`server`** (portale centrale), **`client`** (app satelliti) oppure **`both`**.

---

## Flusso di autenticazione

1. L'utente autenticato sul **Server** clicca su un link verso un'app client (`/center-auth/redirect/{client}?page=/dashboard`) oppure un controller chiama `CenterAuth::redirectToClient(...)`.
2. Il **Server** prepara il payload (`iss`, `sub`, `aud`, `page` e i dati minimi dell'utente), lo salva in cache dietro un **`code` monouso** (64 char hex, chiave cache hashata SHA-256) e reindirizza al callback del client (`?code=...`).
   - Se la richiesta arriva da **Inertia**, utilizza automaticamente `Inertia::location(...)`.
3. Il **Client** riceve `GET /center-auth/callback?code=...` ed esegue una chiamata server-to-server `POST /center-auth/exchange` autenticandosi con `X-Center-Auth-Client-Id` e `X-Center-Auth-Client-Secret`.
4. Il **Server** verifica le credenziali del client, consuma il codice in modo atomico (lock non-bloccante su `LockProvider` + `Cache::pull`), controlla che il codice appartenga a quel client e firma il JWT (`RS256` con `iat`, `nbf`, `exp`, `jti`) al momento dello scambio.
5. Il **Client** verifica firma RS256, `exp`, `iss` e `aud`, sincronizza l'utente locale (senza sovrascrivere la password esistente e senza password hardcoded), effettua il login rigenerando la sessione e reindirizza al path relativo sanificato (`page`).

---

## Installazione

Installa il package tramite Composer nell'app Laravel (sia Server che Client):

```bash
composer require salvatorecervone/laravel-center-auth
```

*(Se non è ancora pubblicato su Packagist e lo installi da repository Git privato o cartella locale, aggiungi il blocco `repositories` nel `composer.json` del progetto prima di eseguire `composer require`.)*

Pubblica il file di configurazione:

```bash
php artisan vendor:publish --tag=center-auth-config
```

---

## Generazione e distribuzione delle chiavi RS256

Il package usa firma asimmetrica **RS256**:
- il **Server** firma i JWT con la **chiave privata** (`private.key`);
- i **Client** verificano la firma con la **chiave pubblica** (`public.key`) — non possono generare token.

### 1. Generare la coppia di chiavi (sul Server)

Esegui sul progetto **Server**:

```bash
php artisan center-auth:keys
```

Opzioni disponibili:
- `--bits=2048` (default `2048`, minimo `2048`; es. `--bits=4096`)
- `--force` per sovrascrivere chiavi esistenti
- `--private=/percorso/custom/private.key` e `--public=/percorso/custom/public.key`

Di default verranno creati:
- `storage/center-auth/private.key` → **solo sul Server** (permessi `0600`)
- `storage/center-auth/public.key` → **da distribuire ai Client** (permessi `0644`)

> **Sicurezza:** aggiungi `storage/center-auth/*.key` al `.gitignore` del progetto. Non committare mai `private.key` su Git e non copiarla mai sui Client.

*(In alternativa puoi generarle anche con OpenSSL: `openssl genrsa -out storage/center-auth/private.key 2048` e `openssl rsa -in storage/center-auth/private.key -pubout -out storage/center-auth/public.key`.)*

### 2. Come recuperare e configurare le chiavi

[`KeyLoader`](src/Support/KeyLoader.php) carica le chiavi in quest'ordine di priorità:
1. Variabile d'ambiente raw (`CENTER_AUTH_PRIVATE_KEY` / `CENTER_AUTH_PUBLIC_KEY`) se valorizzata;
2. File su disco (`CENTER_AUTH_PRIVATE_KEY_PATH` / `CENTER_AUTH_PUBLIC_KEY_PATH`, default `storage/center-auth/private.key` e `storage/center-auth/public.key`).

#### Opzione A — Tramite file (consigliata)
- **Sul Server:** lascia `private.key` in `storage/center-auth/private.key` (nessuna variabile extra necessaria).
- **Su ogni Client:** copia il contenuto di `storage/center-auth/public.key` dal Server in `storage/center-auth/public.key` del Client (oppure imposta `CENTER_AUTH_PUBLIC_KEY_PATH=/percorso/public.key`).

Per leggere velocemente la chiave pubblica dal Server:
```bash
cat storage/center-auth/public.key
```

#### Opzione B — Tramite `.env` (utile su Docker / PaaS senza file persistenti)
Puoi incollare la chiave direttamente nel `.env` su una sola riga sostituendo i ritorni a capo con `\n`:

```bash
# Sul Server, stampa la public.key già formattata per il .env del Client:
awk 'NF {printf "%s\\n", $0}' storage/center-auth/public.key
```

E nel `.env` del **Client**:
```env
CENTER_AUTH_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...\n-----END PUBLIC KEY-----\n"
```

Lo stesso vale eventualmente per `CENTER_AUTH_PRIVATE_KEY` sul **Server**. [`KeyLoader`](src/Support/KeyLoader.php) converte automaticamente `\n` in newline reali.

---

## Configurazione lato Server

`.env`:

```env
CENTER_AUTH_MODE=server
CENTER_AUTH_ISSUER=https://auth.example.com
CENTER_AUTH_CODE_TTL=60
CENTER_AUTH_JWT_TTL=60

# "config" (default, legge da config/center-auth.php) oppure "database" (consigliato con il pannello)
CENTER_AUTH_CLIENT_DRIVER=database

# Abilita il pannello web di gestione app collegate (/center-auth/admin)
CENTER_AUTH_PANEL_ENABLED=true
CENTER_AUTH_PANEL_PREFIX=center-auth/admin
# Opzionale: nome di un Laravel Gate per autorizzare l'accesso al pannello
# CENTER_AUTH_PANEL_GATE=manage-center-auth
CENTER_AUTH_SECRET_GRACE_HOURS=24
```

Se usi `CENTER_AUTH_CLIENT_DRIVER=database`, pubblica ed esegui la migration:

```bash
php artisan vendor:publish --tag=center-auth-migrations
php artisan migrate
```

Per sicurezza il pannello è **chiuso di default (`403 Forbidden`) fuori dall'ambiente `local`**. In produzione/staging autorizza l'accesso impostando `CENTER_AUTH_PANEL_GATE` oppure registrando un callback nel tuo `AppServiceProvider::boot()` (oltre ai middleware in `config/center-auth.php`):

```php
use CenterAuth\Facades\CenterAuth;

CenterAuth::authorizePanelUsing(function ($request): bool {
    return (bool) $request->user()?->is_admin;
});
```

Dal pannello (`/center-auth/admin`) puoi:
- **Creare** nuove app client (genera automaticamente il `client_secret`, mostrato una sola volta insieme allo snippet `.env` pronto da copiare);
- **Modificare** nome, `client_id`, `callback_url`, descrizione e stato;
- **Abilitare / disabilitare** un'app con un clic (blocco immediato su `/redirect` e `/exchange`);
- **Ruotare il `client_secret`** con finestra di grazia configurabile (o revoca immediata con `0` ore);
- **Eliminare** un'app e vedere la data dell'ultimo utilizzo (`last_used_at`).

In alternativa, se preferisci `CENTER_AUTH_CLIENT_DRIVER=config`, dichiara i client direttamente in `config/center-auth.php`:

```php
'server' => [
    'clients' => [
        'app-alpha' => [
            'secret' => env('CENTER_AUTH_CLIENT_ALPHA_SECRET'),
            'callback_url' => env('CENTER_AUTH_CLIENT_ALPHA_CALLBACK'), // es. https://app-alpha.example.com/center-auth/callback
        ],
        'app-beta' => [
            'secret' => env('CENTER_AUTH_CLIENT_BETA_SECRET'),
            'callback_url' => env('CENTER_AUTH_CLIENT_BETA_CALLBACK'),
        ],
    ],
],
```

### Come reindirizzare un utente autenticato verso un client

Via rotta già registrata dal package:
```
GET /center-auth/redirect/app-alpha?page=/dashboard
```

Oppure da un controller con la Facade:
```php
use CenterAuth\Facades\CenterAuth;

return CenterAuth::redirectToClient(
    clientId: 'app-alpha',
    user: $request->user(),
    targetPage: '/dashboard',
    request: $request,
);
```

---

## Configurazione lato Client

`.env`:

```env
CENTER_AUTH_MODE=client
CENTER_AUTH_CLIENT_ID=app-alpha
CENTER_AUTH_CLIENT_SECRET=il-tuo-secret-condiviso
# Obbligatorio: usato per verificare il claim "iss" dei JWT ricevuti
CENTER_AUTH_SERVER_URL=https://auth.example.com
# Opzionale: URL interno per le chiamate back-channel POST /exchange (default: CENTER_AUTH_SERVER_URL)
CENTER_AUTH_SERVER_API_URL=https://auth-internal.example.com
CENTER_AUTH_FALLBACK_URL=https://auth.example.com
CENTER_AUTH_VERIFY_SSL=true
# Opzionale: tolleranza in secondi per piccoli sfasamenti di orologio tra Server e Client (default: 5)
CENTER_AUTH_JWT_LEEWAY=5
```

Il package registra automaticamente la rotta:
```
GET /center-auth/callback
```

### Proteggere le rotte del Client con SSO verso il Server (SP-initiated)

Quando un utente non autenticato apre direttamente un URL del Client (es. `/pagina-x?tab=dettagli`), il Client lo reindirizza automaticamente al Server (`/center-auth/redirect/{client_id}?page=/pagina-x?tab=dettagli`), il Server gestisce il login (o lo salta se la sessione è già attiva) e rimanda l'utente esattamente sulla pagina richiesta.

Puoi configurarlo in **due modi**:

#### Opzione A — Usando il middleware `center-auth` del package (consigliata)

```php
Route::middleware(['web', 'center-auth'])->group(function () {
    Route::get('/pagina-x', [PaginaController::class, 'show']);
});

// Con guard specifico (opzionale, altrimenti usa center-auth.client.guard o il default):
Route::middleware(['web', 'center-auth:admin'])->get('/admin', ...);
```

*(Supporta automaticamente anche visite **Inertia** via `Inertia::location(...)` e risponde `401 JSON` alle richieste API.)*

#### Opzione B — Continuando a usare il middleware standard `auth` di Laravel

Se preferisci lasciare `->middleware('auth')` sulle rotte del Client:

- **Laravel 11 / 12** (`bootstrap/app.php`):
  ```php
  use CenterAuth\Facades\CenterAuth;
  use Illuminate\Http\Request;

  ->withMiddleware(function (Middleware $middleware) {
      $middleware->redirectGuestsTo(fn (Request $request) =>
          CenterAuth::client()->buildServerRedirectUrl(request: $request)
      );
  })
  ```
- **Laravel 10** (`app/Http/Middleware/Authenticate.php`):
  ```php
  use CenterAuth\Facades\CenterAuth;
  use Illuminate\Http\Request;

  protected function redirectTo(Request $request): ?string
  {
      return $request->expectsJson()
          ? null
          : CenterAuth::client()->buildServerRedirectUrl(request: $request);
  }
  ```

> **Nota lato Server:** assicurati che il controller di login del Server termini con `redirect()->intended(...)` (comportamento predefinito di Laravel Breeze, Jetstream e Fortify), così dopo il login riprende automaticamente `/center-auth/redirect/{client}?page=...`.

#### Rotta `/login` lato Client (opzionale ma consigliata)

Se il Client non ha una pagina di login locale (es. `route('login')` mancante o link diretti a `/login`), puoi definirla in `routes/web.php` per inoltrare al Server SSO preservando sia `url.intended` (salvato dal middleware `auth`) sia un eventuale `?page=...`:

```php
use CenterAuth\Facades\CenterAuth;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::get('/login', function (Request $request) {
    $default = config('center-auth.client.default_redirect', '/');

    if ($request->user()) {
        return redirect()->to($default);
    }

    $intended = $request->session()->pull('url.intended');

    if (is_string($intended) && $intended !== '') {
        $path = parse_url($intended, PHP_URL_PATH) ?: '/';
        $query = parse_url($intended, PHP_URL_QUERY);
        $targetPage = $query ? "{$path}?{$query}" : $path;
    } else {
        $targetPage = (string) ($request->query('page') ?: $default);
    }

    return CenterAuth::redirectToServer($targetPage, $request);
})->name('login');
```

#### Esempio con Laravel + Vue SPA (Vue Router con catch-all)

Se le rotte di pagina sono gestite da **Vue Router** e in `routes/web.php` hai una rotta catch-all:

```php
use CenterAuth\Facades\CenterAuth;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::get('/login', function (Request $request) {
    $default = config('center-auth.client.default_redirect', '/');

    if ($request->user()) {
        return redirect()->to($default);
    }

    $targetPage = (string) ($request->query('page') ?: $default);

    return CenterAuth::redirectToServer($targetPage, $request);
})->name('login');

// Proteggi la catch-all escludendo /center-auth/* e /api/*
Route::get('/{any}', fn () => view('app'))
    ->where('any', '^(?!center-auth|api).*$')
    ->middleware('center-auth');
```

E nel frontend Vue (es. interceptor Axios) gestisci l'eventuale scadenza sessione (`401`) sulle chiamate `/api/*` con un redirect full-page del browser (i redirect SSO cross-domain non vanno eseguiti via XHR):

```js
axios.interceptors.response.use(
    (response) => response,
    (error) => {
        if (error.response?.status === 401) {
            const currentPath = window.location.pathname + window.location.search;
            window.location.href = '/login?page=' + encodeURIComponent(currentPath);
        }
        return Promise.reject(error);
    }
);
```

> **Laravel + Inertia + Vue:** non serve alcun interceptor aggiuntivo — [`ClientAuthService::redirectToServer()`](src/Client/ClientAuthService.php) rileva automaticamente l'header `X-Inertia` e risponde con `Inertia::location(...)`, forzando una navigazione full-page verso il Server SSO.

---

## Estensibilità (ruoli, permessi e hook applicativi)

Nel `AppServiceProvider::boot()` puoi agganciare la logica della tua app senza modificare il package:

### Proprietà disponibili su `AuthPayload`
- `$payload->sub`: ID utente sul Server
- `$payload->email`, `$payload->name`: dati utente
- `$payload->page`: path di destinazione sanificato (es. `/inizio`)
- `$payload->userData`: array dei dati utente personalizzati via `resolveUserClaimsUsing`
- `$payload->claim('chiave')`: legge eventuali claim custom nel JWT

### Esempi

```php
use CenterAuth\Data\AuthPayload;
use CenterAuth\Events\UserAuthenticated;
use CenterAuth\Facades\CenterAuth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Session;

// 1. Lato SERVER: personalizza i claim utente nel JWT (es. aggiungi api_token o ruoli)
CenterAuth::resolveUserClaimsUsing(function ($user, string $clientId): array {
    return [
        'id' => $user->getAuthIdentifier(),
        'name' => $user->name,
        'email' => $user->email,
    ];
});

// 2. Lato CLIENT: chiama la tua API permessi (con Bearer token) e blocca il login se non autorizzato
CenterAuth::beforeLoginUsing(function ($user, AuthPayload $payload, $request): bool {
    $response = Http::withToken(config('services.auth_server.token'))
        ->withOptions(['verify' => config('center-auth.client.verify_ssl')])
        ->acceptJson()
        ->get(config('center-auth.client.server_api_url') . '/api/permessi/' . $payload->sub);

    if ($response->failed()) {
        return false; // blocca il login e rimanda a fallback_url
    }

    $permessi = $response->json();
    Session::put('permissions', $permessi);

    // Ritorna false per negare l'accesso, true per completare il login
    return true;
});

// 3. Lato CLIENT: personalizza la risoluzione/creazione dell'utente locale
CenterAuth::resolveUserUsing(function (AuthPayload $payload) {
    return \App\Models\User::where('email', $payload->email)->firstOrFail();
});

// 4. Lato CLIENT: esegui azioni dopo il login (quando l'utente è già autenticato e la sessione rigenerata)
Event::listen(UserAuthenticated::class, function (UserAuthenticated $event): void {
    // Disponibili: $event->user, $event->payload, $event->request
});
```

Eventi emessi:
- `CenterAuth\Events\CodeGenerated`
- `CenterAuth\Events\CodeExchanged`
- `CenterAuth\Events\UserAuthenticated`
- `CenterAuth\Events\AuthenticationFailed`

### API personalizzate firmate in RS256 (`signPayload` / `decodePayload`)

Se vuoi esporre una tua API su **Server** (es. protetta da `auth:sanctum`) che restituisce ruoli o altri dati dentro un JWT firmato `RS256`:

**Lato Server (Controller API):**
```php
use CenterAuth\Facades\CenterAuth;
use Illuminate\Http\Request;

public function permissions(Request $request, int $userId)
{
    $user = \App\Models\User::findOrFail($userId);

    $jwt = CenterAuth::server()->signPayload(
        data: [
            'roles' => $user->getRoleNames()->values()->all(),
            'permissions' => $user->getAllPermissions()->pluck('name')->values()->all(),
        ],
        audience: $request->query('client_id'), // es. "app-alpha"
        ttl: 60,
    );

    return response()->json(['jwt' => $jwt]);
}
```

**Lato Client (es. dentro `CenterAuth::beforeLoginUsing`):**
```php
$response = Http::withToken(config('services.auth_server.token'))
    ->withOptions(['verify' => config('center-auth.client.verify_ssl')])
    ->acceptJson()
    ->get(config('center-auth.client.server_api_url') . '/api/permessi/' . $payload->sub, [
        'client_id' => config('center-auth.client.client_id'),
    ]);

if ($response->failed()) {
    return false;
}

// Verifica firma RS256, exp, iss e aud; lancia InvalidTokenException se non valido
$data = CenterAuth::client()->decodePayload($response->json('jwt'), requireAudience: true);

Session::put('roles', $data['roles'] ?? []);
Session::put('permissions', $data['permissions'] ?? []);
```

---

## Test

```bash
vendor/bin/phpunit --testdox
```
