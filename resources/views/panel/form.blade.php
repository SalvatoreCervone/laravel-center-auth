@extends('center-auth::panel.layout')

@section('title', $isEdit ? "Modifica {$client->name} — CenterAuth" : 'Nuova applicazione — CenterAuth')

@section('header-actions')
    <a href="{{ route('center-auth.panel.index') }}" class="btn">&larr; Torna alla lista</a>
@endsection

@section('content')
    <div class="card">
        <h2 style="margin-top:0; font-size:1.1rem;">
            {{ $isEdit ? "Modifica applicazione: {$client->name}" : 'Registra una nuova applicazione client' }}
        </h2>

        <form method="POST"
              action="{{ $isEdit ? route('center-auth.panel.clients.update', $client) : route('center-auth.panel.clients.store') }}">
            @csrf
            @if ($isEdit)
                @method('PUT')
            @endif

            <div class="form-group">
                <label for="name">Nome applicazione</label>
                <input id="name" name="name" type="text" class="form-control"
                       value="{{ old('name', $client->name) }}"
                       placeholder="Es. Portale Ticket" required maxlength="120">
                @error('name')
                    <div class="error-text">{{ $message }}</div>
                @enderror
            </div>

            <div class="form-group">
                <label for="client_id">Client ID (slug univoco)</label>
                <input id="client_id" name="client_id" type="text" class="form-control"
                       value="{{ old('client_id', $client->client_id) }}"
                       placeholder="Es. portale-ticket"
                       pattern="^[a-z0-9][a-z0-9_-]*$"
                       required maxlength="80">
                <div class="help">Solo lettere minuscole, numeri, trattini (<code>-</code>) e underscore (<code>_</code>). Deve coincidere con <code>CENTER_AUTH_CLIENT_ID</code> sull'app client.</div>
                @error('client_id')
                    <div class="error-text">{{ $message }}</div>
                @enderror
            </div>

            <div class="form-group">
                <label for="callback_url">Callback URL</label>
                <input id="callback_url" name="callback_url" type="url" class="form-control"
                       value="{{ old('callback_url', $client->callback_url) }}"
                       placeholder="https://app-client.example.com/center-auth/callback"
                       required maxlength="255">
                <div class="help">URL completo dell'endpoint <code>/center-auth/callback</code> esposto dall'app client.</div>
                @error('callback_url')
                    <div class="error-text">{{ $message }}</div>
                @enderror
            </div>

            <div class="form-group">
                <label for="description">Descrizione (opzionale)</label>
                <textarea id="description" name="description" rows="2" class="form-control"
                          maxlength="500" placeholder="Note interne sull'applicazione">{{ old('description', $client->description) }}</textarea>
                @error('description')
                    <div class="error-text">{{ $message }}</div>
                @enderror
            </div>

            <div class="form-group">
                <label class="checkbox-row" for="is_active">
                    <input type="hidden" name="is_active" value="0">
                    <input id="is_active" name="is_active" type="checkbox" value="1"
                           {{ old('is_active', $client->is_active) ? 'checked' : '' }}>
                    <span>Applicazione abilitata all'autenticazione</span>
                </label>
            </div>

            <div style="display:flex; gap:0.6rem; margin-top:1.25rem;">
                <button type="submit" class="btn btn-primary">
                    {{ $isEdit ? 'Salva modifiche' : 'Crea applicazione e genera secret' }}
                </button>
                <a href="{{ route('center-auth.panel.index') }}" class="btn">Annulla</a>
            </div>
        </form>
    </div>

    @if ($isEdit)
        <div class="card">
            <h2 style="margin-top:0; font-size:1.05rem;">Rotazione Client Secret</h2>
            <p class="muted" style="margin-top:0;">
                Genera un nuovo <code>CENTER_AUTH_CLIENT_SECRET</code> per questa applicazione.
                Puoi impostare una finestra di grazia (in ore) durante la quale sia il vecchio che il nuovo secret restano validi, così da aggiornare il client senza disservizi.
                Imposta <code>0</code> per revocare subito il vecchio secret.
            </p>

            @if ($client->hasActivePreviousSecret())
                <div class="alert alert-warning">
                    È già attiva una finestra di rotazione: il vecchio secret scadrà il
                    <strong>{{ $client->previous_secret_expires_at->format('d/m/Y H:i') }}</strong>.
                </div>
            @endif

            <form method="POST" action="{{ route('center-auth.panel.clients.rotate-secret', $client) }}"
                  onsubmit="return confirm('Generare un nuovo secret per {{ addslashes($client->name) }}?');"
                  style="display:flex; flex-wrap:wrap; align-items:flex-end; gap:0.75rem;">
                @csrf
                <div class="form-group" style="margin-bottom:0; max-width:220px;">
                    <label for="grace_hours">Finestra di grazia (ore)</label>
                    <input id="grace_hours" name="grace_hours" type="number" min="0" max="720"
                           class="form-control" value="{{ old('grace_hours', $defaultGraceHours) }}">
                </div>
                <button type="submit" class="btn btn-danger">Ruota Client Secret</button>
            </form>
        </div>
    @endif
@endsection
