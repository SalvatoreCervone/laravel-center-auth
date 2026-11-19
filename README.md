# Laravel Center Auth

Componente Laravel leggero per autenticazione SSO in stile OAuth2 (**Authorization Code + JWT firmato RS256**), senza dover installare Laravel Passport.

Un unico package configurabile in modalità **`server`** (portale centrale), **`client`** (app satelliti) oppure **`both`**.

---

## Flusso di autenticazione

1. L'utente autenticato sul **Server** clicca su un link verso un'app client (`/center-auth/redirect/{client}?page=/dashboard`) oppure un controller chiama `CenterAuth::redirectToClient(...)`.
2. Il **Server** firma un JWT (`RS256`) con `iss`, `sub`, `aud`, `iat`, `nbf`, `exp`, `jti`, `page` e i dati minimi dell'utente, lo salva in cache dietro un **`code` monouso** (64 char hex, chiave cache hashata SHA-256) e reindirizza al callback del client (`?code=...`).
   - Se la richiesta arriva da **Inertia**, utilizza automaticamente `Inertia::location(...)`.
3. Il **Client** riceve `GET /center-auth/callback?code=...` ed esegue una chiamata server-to-server `POST /center-auth/exchange` autenticandosi con `X-Center-Auth-Client-Id` e `X-Center-Auth-Client-Secret`.
4. Il **Server** verifica le credenziali del client, consuma il codice in modo atomico (`Cache::pull`), controlla che il codice appartenga a quel client e restituisce il JWT.
5. Il **Client** verifica firma RS256, `exp`, `iss` e `aud`, sincronizza l'utente locale (senza sovrascrivere la password esistente e senza password hardcoded), effettua il login rigenerando la sessione e reindirizza al path relativo sanificato (`page`).

---

## Installazione

Installa il package tramite Composer nell'app Laravel (sia Server che Client):

```bash
composer require center-auth/laravel-center-auth
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
CENTER_AUTH_SECRET_GRACE_HOURS=24
```

Se usi `CENTER_AUTH_CLIENT_DRIVER=database`, pubblica ed esegui la migration:

```bash
php artisan vendor:publish --tag=center-auth-migrations
php artisan migrate
```

Puoi limitare l'accesso al pannello nel tuo `AppServiceProvider::boot()` (oltre ai middleware in `config/center-auth.php`):

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
CENTER_AUTH_SERVER_URL=https://auth.example.com
CENTER_AUTH_SERVER_API_URL=https://auth-internal.example.com
CENTER_AUTH_FALLBACK_URL=https://auth.example.com
CENTER_AUTH_VERIFY_SSL=true
```

Il package registra automaticamente la rotta:
```
GET /center-auth/callback
```

---

## Estensibilità (pronto per ruoli e permessi)

Nel `AppServiceProvider::boot()` puoi agganciare logica applicativa senza modificare il package:

```php
use CenterAuth\Data\AuthPayload;
use CenterAuth\Facades\CenterAuth;

// Lato SERVER: personalizza i claim utente nel JWT
CenterAuth::resolveUserClaimsUsing(function ($user, string $clientId): array {
    return [
        'id' => $user->getAuthIdentifier(),
        'name' => $user->name,
        'email' => $user->email,
    ];
});

// Lato CLIENT: controlla permessi/ruoli prima di completare il login
CenterAuth::beforeLoginUsing(function ($user, AuthPayload $payload, $request): bool {
    // Ritorna false per bloccare il login e reindirizzare a fallback_url
    return true;
});

// Lato CLIENT: personalizza la risoluzione/creazione dell'utente locale
CenterAuth::resolveUserUsing(function (AuthPayload $payload) {
    return \App\Models\User::where('email', $payload->email)->firstOrFail();
});
```

Eventi emessi:
- `CenterAuth\Events\CodeGenerated`
- `CenterAuth\Events\CodeExchanged`
- `CenterAuth\Events\UserAuthenticated`
- `CenterAuth\Events\AuthenticationFailed`

---

## Test

```bash
vendor/bin/phpunit --testdox
```
