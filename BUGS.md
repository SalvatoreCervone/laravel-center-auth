# Audit Bug e Modifiche da Fare — `laravel-center-auth`

Questo documento elenca i bug di sicurezza, logica, concorrenza e qualità individuati nel package, con le relative modifiche proposte e i test da aggiungere.

---

## Riepilogo

| # | Severità | Area | File principali | Stato |
|---|----------|------|-----------------|-------|
| 1 | **Critico** | Sicurezza (Access Control) | `src/CenterAuthManager.php`, `config/center-auth.php` | [x] Risolto |
| 2 | **Alto** | Logica / TTL | `src/Server/ServerAuthService.php` | [x] Risolto |
| 3 | **Alto** | Sicurezza / Concorrenza | `src/Server/ServerAuthService.php` | [x] Risolto |
| 4 | **Medio** | Sicurezza (JWT `iss`) | `src/Client/ClientAuthService.php` | [x] Risolto |
| 5 | **Medio** | Sicurezza (Token Confusion) | `src/Server/ServerAuthService.php`, `src/Client/ClientAuthService.php` | [x] Risolto |
| 6 | **Medio** | Concorrenza (DB) | `src/Client/UserSynchronizer.php` | [x] Risolto |
| 7 | **Medio-Basso** | UI / Escape JS | `resources/views/panel/index.blade.php`, `resources/views/panel/form.blade.php` | [x] Risolto |
| 8 | **Basso** | Routing / URL | `src/Client/ClientAuthService.php`, `resources/views/panel/index.blade.php` | [x] Risolto |
| 9 | **Basso** | CLI / Sicurezza File | `src/Console/GenerateKeysCommand.php` | [x] Risolto |
| 10 | **Basso** | UX / Resilienza | `src/Server/Http/Controllers/ClientPanelController.php` | [x] Risolto |

---

## Dettaglio Bug e Modifiche

### 1. [Critico] Pannello admin *fail-open* di default

**File coinvolti:**
- `src/CenterAuthManager.php` (righe 122–129)
- `src/Server/Http/Middleware/AuthorizePanel.php`
- `tests/Feature/ClientPanelTest.php`
- `README.md`

**Problema:**
`CenterAuthManager::canAccessPanel()` restituisce `true` se non è stato registrato alcun callback con `CenterAuth::authorizePanelUsing(...)`:

```php
public function canAccessPanel(Request $request): bool
{
    if ($this->panelAuthorizer === null) {
        return true;
    }

    return (bool) ($this->panelAuthorizer)($request);
}
```

**Impatto:**
Se si imposta `CENTER_AUTH_PANEL_ENABLED=true` dimenticando di configurare `CenterAuth::authorizePanelUsing(...)`, qualsiasi utente autenticato sul server centrale (anche non amministratore) può accedere a `/center-auth/admin`, creare/eliminare applicazioni client, modificare `callback_url` (dirottando i codici SSO) o ruotare i secret.

**Modifiche da fare:**
- Cambiare il comportamento di default in *fail-closed* (`return false;`), oppure consentire l'accesso senza authorizer solo in ambiente `local` (`$this->app->environment('local')`), documentandolo chiaramente nel `README.md`.
- Aggiornare i test in `tests/Feature/ClientPanelTest.php` per registrare esplicitamente `CenterAuth::authorizePanelUsing(...)` e aggiungere un test che verifichi il `403 Forbidden` quando non è configurato alcun authorizer.

> **💬 Commento / Come lo farei — Firmato: *Gemini 4 Argon***
> Un `return false;` secco senza opzioni aggiuntive costringerebbe chiunque a scrivere codice custom in `AppServiceProvider` anche quando usa già un Gate o un middleware dedicato in `center-auth.server.panel.middleware`.
> Io lo risolverei in modo più idiomatico (stile Laravel Horizon/Pulse):
> 1. Aggiungere in `config/center-auth.php` una chiave opzionale `'gate' => env('CENTER_AUTH_PANEL_GATE')` dentro `server.panel`.
> 2. In `canAccessPanel(Request $request)`:
>    - Se è registrato `$this->panelAuthorizer`, usare quello.
>    - Altrimenti, se è configurato `center-auth.server.panel.gate`, verificare `Gate::forUser($request->user())->allows($gate)`.
>    - Altrimenti, consentire l'accesso solo in ambiente locale (`return $this->app->environment('local');`), fallendo chiuso (`403`) in tutti gli altri ambienti (`production`, `staging`, ecc.).

---

### 2. [Alto] JWT firmato in `issueCode()` invece che in `exchangeCode()` (`jwt_ttl` vs `code_ttl`)

**File coinvolti:**
- `src/Server/ServerAuthService.php` (righe 40–86 e 155–182)
- `config/center-auth.php` (righe 60–65)

**Problema:**
In `ServerAuthService::issueCode()`, il JWT viene firmato subito con `exp = $now + $jwtTtl` e salvato in cache per `$codeTtl` secondi.
Questo contraddice anche il commento in `config/center-auth.php` (*"Lifetime in seconds of the signed JWT returned by /exchange"*).

**Impatto:**
Se `code_ttl > jwt_ttl` (oppure se il redirect del browser richiede diversi secondi prima che il client chiami `/exchange`), il codice è ancora valido in cache, `/exchange` risponde `200 OK`, ma il JWT restituito è già scaduto e fallisce la verifica lato client.

**Modifiche da fare:**
- In `issueCode()`, salvare in cache i dati necessari a costruire il JWT (`client_id`, `sub`, `page`, `user`, `extra_claims`) invece del JWT già firmato.
- In `exchangeCode()`, dopo aver validato credenziali e consumato il codice, costruire e firmare il JWT al momento dello scambio usando `$now = time()` e `exp = $now + $jwtTtl`.
- Aggiungere un test in `tests/Feature/ServerAuthTest.php` con `code_ttl > jwt_ttl` (es. avanzando il tempo con `Carbon::setTestNow` / `travel`) che verifichi che il JWT rilasciato da `/exchange` sia valido per `jwt_ttl` secondi a partire dallo scambio.

> **💬 Commento / Come lo farei — Firmato: *Gemini 4 Argon***
> La soluzione di posticipare la firma a `exchangeCode()` è giusta, ma **attenzione a un effetto collaterale**: se sposti `getIssuer()` e `keyLoader->loadPrivateKey()` dentro `exchangeCode()`, un eventuale errore di configurazione sul server (es. `issuer` mancante o `private.key` non leggibile) non fallirà più subito durante `issueCode()` (`/redirect`), ma solo in back-channel su `/exchange` dopo aver già rediretto il browser dell'utente al client.
> **Come lo farei:**
> - In `issueCode()` validare **subito** `$this->getIssuer()` e `$this->keyLoader->loadPrivateKey()` (fail-fast) e risolvere subito `$this->manager->resolveUserClaims($user, $clientId)` (perché l'istanza `Authenticatable` è disponibile qui, senza dover ricaricare l'utente dal DB in `exchangeCode()`).
> - Salvare in cache il payload pre-assemblato (senza `iat`, `nbf`, `exp`, `jti`) insieme a `client_id`.
> - In `exchangeCode()` aggiungere `iat`, `nbf`, `exp = time() + $jwtTtl`, `jti` e firmare il JWT con `JWT::encode(...)`.

---

### 3. [Alto] `Cache::pull()` non è atomico (race condition su codice monouso)

**File coinvolti:**
- `src/Server/ServerAuthService.php` (righe 167–171)

**Problema:**
`exchangeCode()` usa `$this->cache()->pull($this->cacheKey($code))`. In Laravel `Illuminate\Cache\Repository::pull()` esegue `get()` seguito da `forget()`, che **non è un'operazione atomica** su gran parte degli store.

**Impatto:**
Due richieste `POST /exchange` concorrenti con lo stesso `code` possono leggere entrambe il record prima che venga eliminato ed entrambe ricevere il JWT. Poiché il client non traccia `jti` per prevenire replay, il codice può essere usato più di una volta.

**Modifiche da fare:**
- Wrappare la lettura + rimozione del codice in un lock atomico se lo store implementa `Illuminate\Contracts\Cache\LockProvider` (es. `$store->lock($cacheKey . ':lock', 5)->block(3, fn () => ...)`), facendo `get()` + `forget()` dentro il lock.
- In alternativa (o in aggiunta per Redis), usare `GETDEL` se supportato.
- Aggiungere un test unitario/feature che verifichi il comportamento con lock e il rifiuto del secondo tentativo.

> **💬 Commento / Come lo farei — Firmato: *Gemini 4 Argon***
> Nella soluzione proposta ci sono **due errori tecnici**:
> 1. `$this->cache()` restituisce `Illuminate\Contracts\Cache\Repository`, che **non** implementa `LockProvider`: è `$this->cache()->getStore()` (lo `Store` sottostante) a implementare `LockProvider`.
> 2. Usare `->block(3, ...)` su un codice monouso è controproducente: se due richieste arrivano in parallelo con lo **stesso** `code`, la seconda non ha alcun motivo di restare bloccata 3 secondi occupando un worker PHP-FPM solo per scoprire che il codice è stato appena bruciato dalla prima.
>
> **Come lo farei:**
> ```php
> $cacheKey = $this->cacheKey($code);
> $store = $this->cache()->getStore();
>
> if ($store instanceof LockProvider) {
>     $lock = $store->lock($cacheKey . ':lock', 5);
>     if (! $lock->get()) {
>         throw new CodeExchangeException('Authorization code is invalid or expired.');
>     }
>     try {
>         $record = $this->cache()->pull($cacheKey);
>     } finally {
>         $lock->release();
>     }
> } else {
>     $record = $this->cache()->pull($cacheKey);
> }
> ```
> Così l'acquisizione è non-bloccante (`$lock->get()`), immediata e sicura su tutti i driver cache di Laravel.

---

### 4. [Medio] Verifica di `iss` saltata silenziosamente se `server_url` è vuoto

**File coinvolti:**
- `src/Client/ClientAuthService.php` (righe 117–122 e 173–178)

**Problema:**
Sia in `verifyJwt()` che in `decodePayload()`:

```php
$expectedIssuer = rtrim((string) config('center-auth.client.server_url', ''), '/');
$actualIssuer = rtrim((string) ($claims['iss'] ?? ''), '/');

if ($expectedIssuer !== '' && ($actualIssuer === '' || ! hash_equals($expectedIssuer, $actualIssuer))) {
    throw new InvalidTokenException('JWT issuer (iss) does not match configured server_url.');
}
```

Se `server_url` non è configurato (es. il client ha impostato solo `CENTER_AUTH_SERVER_API_URL`), la condizione `$expectedIssuer !== ''` è falsa e il controllo su `iss` viene saltato del tutto.

**Impatto:**
Un errore di configurazione disattiva silenziosamente la validazione dell'issuer.

**Modifiche da fare:**
- Se `$expectedIssuer === ''`, lanciare `InvalidConfigurationException('CenterAuth client server_url (center-auth.client.server_url) is not configured.')` invece di saltare il controllo.
- Aggiungere un test in `tests/Feature/ClientAuthTest.php` e `tests/Feature/SignedPayloadTest.php` che verifichi l'eccezione quando `server_url` manca.

> **💬 Commento / Come lo farei — Firmato: *Gemini 4 Argon***
> La soluzione è corretta: `server_url` deve essere obbligatorio per validare `iss` (mentre `server_api_url` resta opzionale per il solo traffico back-channel interno es. Docker/K8s).
> Un piccolo miglioramento: oltre a controllare `$expectedIssuer === ''` (che lancia `InvalidConfigurationException`), estrarrei un metodo privato `verifyIssuer(array $claims): string` in `ClientAuthService` per non duplicare la stessa logica identica tra `verifyJwt()` e `decodePayload()`.

---

### 5. [Medio] Token confusion tra JWT di login SSO e `signPayload()`

**File coinvolti:**
- `src/Server/ServerAuthService.php` (righe 59–69 e 101–108)
- `src/Client/ClientAuthService.php` (righe 97–152 e 160–192)

**Problema:**
1. I JWT generati da `issueCode()` e quelli generati da `signPayload()` usano la stessa chiave RS256 ma non includono alcun claim di tipo/scopo (es. `typ` o `purpose`).
2. `ClientAuthService::decodePayload()` restituisce `is_array($claims['data'] ?? null) ? $claims['data'] : $claims`: se gli viene passato un JWT di login SSO (che non ha il claim `data`), lo accetta comunque e restituisce tutti i claims dell'SSO.

**Impatto:**
Un token emesso per il login SSO può essere accettato impropriamente da endpoint che usano `decodePayload()` (cross-purpose token acceptance).

**Modifiche da fare:**
- Aggiungere un claim esplicito di tipo/scopo (es. `'purpose' => 'sso'` nei token di `issueCode()` e `'purpose' => 'payload'` nei token di `signPayload()`, inserendo `'purpose'` anche in `RESERVED_CLAIMS`).
- In `ClientAuthService::verifyJwt()`, verificare che `($claims['purpose'] ?? 'sso') === 'sso'` (o renderlo obbligatorio se non serve retrocompatibilità).
- In `ClientAuthService::decodePayload()`, verificare che `$claims['purpose'] === 'payload'` e che `is_array($claims['data'] ?? null)` sia vero, altrimenti lanciare `InvalidTokenException`.
- Aggiungere un test in `tests/Feature/SignedPayloadTest.php` che verifichi che un JWT SSO venga rifiutato da `decodePayload()` e viceversa.

> **💬 Commento / Come lo farei — Firmato: *Gemini 4 Argon***
> Introdurre un claim custom obbligatorio `'purpose' => 'payload'` in `decodePayload()` **rompe i test esistenti** (`SignedPayloadTest::test_decode_payload_rejects_wrong_issuer` costruisce manualmente un JWT con `'data' => [...]` senza `'purpose'`) e rompe eventuali integrazioni esterne che firmano un payload standard con claim `data`.
> In realtà la *token confusion* nasce da due soli dettagli:
> 1. `RESERVED_CLAIMS` in `ServerAuthService` (`['iss', 'sub', 'aud', 'iat', 'nbf', 'exp', 'jti']`) non include `'data'`, `'user'` e `'page'` (quindi `$extraClaims` in `issueCode()` potrebbe iniettare `'data' => [...]` dentro un token SSO!).
> 2. `decodePayload()` fa il fallback `: $claims` quando `$claims['data']` non esiste.
>
> **Come lo farei (senza rompere retrocompatibilità):**
> 1. Aggiungere `'data'`, `'user'`, `'page'` a `ServerAuthService::RESERVED_CLAIMS`, così un token SSO non potrà **mai** contenere una chiave top-level `data`.
> 2. In `ClientAuthService::decodePayload()`, rimuovere il fallback `: $claims` e richiedere obbligatoriamente che `isset($claims['data']) && is_array($claims['data'])` (e che `! isset($claims['user'])`), lanciando `InvalidTokenException('JWT payload is missing required data claim.')` in caso contrario.
> In questo modo un token SSO e un token `signPayload()` sono strutturalmente disgiunti al 100% senza bisogno di claim proprietari.

---

### 6. [Medio] Race condition al primo login in `UserSynchronizer::sync()`

**File coinvolti:**
- `src/Client/UserSynchronizer.php` (righe 29–42)

**Problema:**
Al primo accesso di un utente nuovo, due richieste concorrenti su `/callback` eseguono entrambe `where('email', $payload->email)->first()`, ottengono `null` e tentano `$user->save()`. La seconda fallisce con `UniqueConstraintViolationException` / `QueryException`. Poiché `ClientAuthService::handleCallback()` cattura solo `CenterAuthException`, l'utente riceve un errore `500`.

**Modifiche da fare:**
- Gestire `Illuminate\Database\UniqueConstraintViolationException` (e/o `QueryException` per compatibilità Laravel 10) durante il `save()` iniziale: in caso di conflitto di unicità, rieseguire la query `where('email', $payload->email)->first()` e restituire l'utente appena creato dall'altra richiesta.
- Aggiungere un test unitario/feature per verificare la gestione del conflitto.

> **💬 Commento / Come lo farei — Firmato: *Gemini 4 Argon***
> Attenzione a non catturare `QueryException` alla cieca: se `$user->save()` fallisse per un altro motivo (es. colonna mancante o vincolo `NOT NULL` su un campo custom del modello `User`), restituire `null` causerebbe un errore fuorviante più avanti.
> **Come lo farei:**
> ```php
> try {
>     $user->save();
> } catch (QueryException $e) {
>     $existing = $modelClass::query()->where('email', $payload->email)->first();
>     if ($existing !== null) {
>         return $existing;
>     }
>
>     throw $e;
> }
> ```
> Se la rilettura trova l'utente, era davvero una race condition su `email` e la gestiamo; altrimenti rilanciamo l'eccezione originale `$e`.

---

### 7. [Medio-Basso] Escape JS fragile con `addslashes()` nelle viste Blade

**File coinvolti:**
- `resources/views/panel/index.blade.php` (riga 113)
- `resources/views/panel/form.blade.php` (riga 101)

**Problema:**
I dialog di conferma usano:

```blade
onsubmit="return confirm('Eliminare definitivamente l\'applicazione {{ addslashes($client->name) }}?');"
```

La validazione lato controller (`'name' => ['required', 'string', 'max:120']`) ammette newline (`\n`, `\r`), che `addslashes()` non escapa. Un newline nel nome produce un `SyntaxError` in JavaScript che invalida l'handler `onsubmit` (saltando la conferma).

**Modifiche da fare:**
- Sostituire `addslashes(...)` con `\Illuminate\Support\Js::from(...)` oppure spostare il messaggio in un attributo `data-confirm="..."` gestito da un listener JS:

```blade
onsubmit="return confirm({{ \Illuminate\Support\Js::from("Eliminare definitivamente l'applicazione {$client->name}?") }});"
```

- Aggiungere un test in `tests/Feature/ClientPanelTest.php` con un nome client contenente apici, virgolette e newline.

> **💬 Commento / Come lo farei — Firmato: *Gemini 4 Argon***
> **La soluzione con `Js::from(...)` proposta qui sopra è errata e rompe l'HTML!**
> `Js::from(...)` restituisce un oggetto `Illuminate\Support\Js` che implementa `Htmlable`: Blade quindi **non** applica `htmlspecialchars()` e stampa direttamente virgolette doppie letterali (`"Eliminare..."` o `JSON.parse('...')`) **dentro** l'attributo HTML delimitato a sua volta da virgolette doppie `onsubmit="..."`, troncando l'attributo HTML e aprendo persino a iniezione di attributi!
>
> **Come lo farei (pulito, sicuro al 100% e zero JS inline dinamico):**
> Usare un attributo HTML `data-confirm` (che viene normalmente escapato da Blade con `{{ ... }}` per il contesto attributo HTML) e leggerlo via `this.dataset.confirm`:
> ```blade
> data-confirm="Eliminare definitivamente l'applicazione {{ $client->name }}?"
> onsubmit="return confirm(this.dataset.confirm);"
> ```
> In questo modo Blade gestisce il solo contesto HTML (`&quot;`, `&#039;`, newline inclusi) e il browser passa la stringa già decodificata a `confirm()` senza alcuna concatenazione di codice JS.

---

### 8. [Basso] Doppio slash se `route_prefix` è vuoto (`''` o `'/'`)

**File coinvolti:**
- `src/Client/ClientAuthService.php` (righe 45 e 63)
- `resources/views/panel/index.blade.php` (riga 86)

**Problema:**
Se `center-auth.route_prefix` è configurato come `''` o `'/'`, `$prefix` diventa `''` e:
- `ClientAuthService::exchangeCode()` genera `"{$apiBaseUrl}//exchange"` invece di `"{$apiBaseUrl}/exchange"`.
- `index.blade.php` mostra `//redirect/{client_id}` invece di `/redirect/{client_id}`.

**Modifiche da fare:**
- Costruire il path dinamicamente:
  ```php
  $exchangePath = $prefix !== '' ? "/{$prefix}/exchange" : '/exchange';
  $exchangeUrl = $apiBaseUrl . $exchangePath;
  ```
- In `index.blade.php`, usare `route('center-auth.server.redirect', $client->client_id, false)` oppure condizionare lo slash su `$routePrefix !== ''`.
- Aggiungere un test con `route_prefix = ''`.

---

### 9. [Basso] Scrittura chiave privata non sicura e errori I/O ignorati in `GenerateKeysCommand`

**File coinvolti:**
- `src/Console/GenerateKeysCommand.php` (righe 62–83)

**Problema:**
1. `file_put_contents($privatePath, $privateKey)` crea il file con i permessi di default dell'umask (tipicamente `0644`, leggibile da altri utenti sul sistema) e solo dopo esegue `@chmod($privatePath, 0600)`, lasciando una finestra temporale esposta.
2. Non vengono controllati i valori di ritorno di `mkdir()` e `file_put_contents()`: in caso di disco pieno o directory non scrivibile, il comando stampa comunque successo e restituisce `self::SUCCESS`.

**Modifiche da fare:**
- Impostare `umask(0077)` (o creare il file con `touch` + `chmod(..., 0600)` prima di scrivere, oppure scrivere in file temporaneo con `0600` e `rename`) in modo che la chiave privata non sia mai leggibile da altri utenti.
- Controllare il risultato di `mkdir()` e `file_put_contents()` (e `chmod()`), restituendo `self::FAILURE` con un messaggio d'errore chiaro in caso di fallimento.
- Aggiungere un test in `tests/Feature/GenerateKeysCommandTest.php` per i permessi e il caso di path non scrivibile.

> **💬 Commento / Come lo farei — Firmato: *Gemini 4 Argon***
> Usare `umask(0077)` senza ripristinarla modifica lo stato globale del processo PHP (problematico nei test o se il comando viene chiamato programmaticamente con `Artisan::call()`), e soprattutto `umask` **non restringe** i permessi di un file già esistente quando si usa `--force`!
> **Come lo farei:**
> 1. Ripristinare sempre l'`umask` in un blocco `try / finally` **e** forzare `chmod($privatePath, 0600)` subito dopo (così copre sia la creazione ex-novo sia la sovrascrittura con `--force`).
> 2. Verificare esplicitamente `file_put_contents(...) === false` sia sulla chiave privata che pubblica, stampando un errore con `$this->components->error(...)` e restituendo `self::FAILURE`.

---

### 10. [Basso] Crash 500 in `ClientPanelController::index()` con driver `config` senza migration

**File coinvolti:**
- `src/Server/Http/Controllers/ClientPanelController.php` (righe 15–29)
- `resources/views/panel/index.blade.php` (righe 10–15)

**Problema:**
La vista `panel/index.blade.php` mostra un banner di avviso se `driver !== 'database'`, ma `ClientPanelController::index()` esegue comunque `CenterAuthClient::query()->...->get()` prima di renderizzare la vista. Se il progetto usa il driver `config` e non ha ancora eseguito le migration, la pagina va in crash `500` (`QueryException: table center_auth_clients doesn't exist`) invece di mostrare il banner.

**Modifiche da fare:**
- Controllare `Schema::hasTable((new CenterAuthClient())->getTable())` (o gestire il caso `driver !== 'database'` se la tabella non esiste) restituendo una `Collection` vuota così che la vista possa mostrare correttamente il banner di avviso.
- Aggiungere un test in `tests/Feature/ClientPanelTest.php` con `driver = 'config'` senza tabella migrata.

> **💬 Commento / Come lo farei — Firmato: *Gemini 4 Argon***
> Eseguire `Schema::hasTable('center_auth_clients')` a ogni apertura del pannello introduce una query extra su `information_schema` / `sqlite_master` a ogni richiesta anche quando tutto è configurato correttamente.
> **Come lo farei:**
> Eseguire normalmente la query `CenterAuthClient::query()->...->get()` dentro un `try / catch (QueryException)` (oppure saltarla se `$driver !== 'database'` e la query fallisce), restituendo `collect()` in caso di tabella mancante. In questo modo il percorso normale ha **zero query extra**, e in caso di migration non ancora eseguita la pagina mostra comunque il banner di avviso senza andare in errore 500.

---

## Ordine di implementazione consigliato

1. **Priorità 1 (Sicurezza immediata)**: Bug #1 (panel fail-closed), #3 (consumo atomico del codice), #4 (`iss` obbligatorio), #5 (token confusion).
2. **Priorità 2 (Correttezza funzionale)**: Bug #2 (firma JWT in `exchangeCode()`), #6 (race condition `UserSynchronizer`).
3. **Priorità 3 (Hardening & UX)**: Bug #7 (Blade `Js::from`), #8 (`route_prefix` vuoto), #9 (`GenerateKeysCommand`), #10 (`ClientPanelController` senza migration).
