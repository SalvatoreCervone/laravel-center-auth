@extends('center-auth::panel.layout')

@section('title', 'CenterAuth — Applicazioni collegate')

@section('header-actions')
    <a href="{{ route('center-auth.panel.clients.create') }}" class="btn btn-primary">+ Nuova applicazione</a>
@endsection

@section('content')
    @if ($driver !== 'database')
        <div class="alert alert-warning" role="alert">
            <strong>Attenzione:</strong> il driver attivo è <code>{{ $driver }}</code>.
            Per usare le applicazioni gestite da questo pannello imposta <code>CENTER_AUTH_CLIENT_DRIVER=database</code> nel file <code>.env</code> del server.
        </div>
    @endif

    @if (session('generated_secret'))
        <div class="card" role="region" aria-label="Client secret generato">
            <div style="display:flex; justify-content:space-between; align-items:center; gap:1rem; flex-wrap:wrap;">
                <strong>Copia subito il Client Secret (mostrato una sola volta)</strong>
                <button type="button" class="btn btn-sm" onclick="copyText('generated-env-snippet', this)">Copia snippet .env</button>
            </div>
            <p class="muted" style="margin:0.4rem 0 0.5rem;">
                Per sicurezza il secret viene salvato solo come hash nel database e non sarà più visibile dopo aver lasciato questa pagina.
            </p>
            <pre id="generated-env-snippet">CENTER_AUTH_MODE=client
CENTER_AUTH_CLIENT_ID={{ session('generated_client_id') }}
CENTER_AUTH_CLIENT_SECRET={{ session('generated_secret') }}
CENTER_AUTH_SERVER_URL={{ $issuer }}
CENTER_AUTH_SERVER_API_URL={{ $issuer }}
CENTER_AUTH_FALLBACK_URL={{ $issuer }}
# CENTER_AUTH_VERIFY_SSL=false</pre>
        </div>
    @endif

    <div class="stats">
        <div class="stat-card">
            <div class="label">Totale app</div>
            <div class="value">{{ $clients->count() }}</div>
        </div>
        <div class="stat-card">
            <div class="label">Attive</div>
            <div class="value">{{ $clients->where('is_active', true)->count() }}</div>
        </div>
        <div class="stat-card">
            <div class="label">Disabilitate</div>
            <div class="value">{{ $clients->where('is_active', false)->count() }}</div>
        </div>
    </div>

    <div class="card">
        @if ($clients->isEmpty())
            <p class="muted" style="margin:0;">
                Nessuna applicazione collegata. Clicca su <strong>+ Nuova applicazione</strong> per registrarne una.
            </p>
        @else
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Applicazione</th>
                            <th>Client ID</th>
                            <th>Callback URL</th>
                            <th>Stato</th>
                            <th>Ultimo accesso</th>
                            <th>Azioni</th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach ($clients as $client)
                            <tr>
                                <td>
                                    <strong>{{ $client->name }}</strong>
                                    @if ($client->description)
                                        <div class="muted">{{ $client->description }}</div>
                                    @endif
                                    @if ($client->hasActivePreviousSecret())
                                        <div style="margin-top:0.25rem;">
                                            <span class="badge badge-warn">Rotazione secret in corso fino al {{ $client->previous_secret_expires_at->format('d/m H:i') }}</span>
                                        </div>
                                    @endif
                                </td>
                                <td>
                                    <code>{{ $client->client_id }}</code>
                                    <div class="muted" style="margin-top:0.2rem;">
                                        <code>/{{ $routePrefix }}/redirect/{{ $client->client_id }}</code>
                                    </div>
                                </td>
                                <td><code>{{ $client->callback_url }}</code></td>
                                <td>
                                    @if ($client->is_active)
                                        <span class="badge badge-active">Attiva</span>
                                    @else
                                        <span class="badge badge-disabled">Disabilitata</span>
                                    @endif
                                </td>
                                <td class="muted">
                                    {{ $client->last_used_at ? $client->last_used_at->format('d/m/Y H:i') : 'Mai' }}
                                </td>
                                <td>
                                    <div class="actions">
                                        <form method="POST" action="{{ route('center-auth.panel.clients.toggle', $client) }}">
                                            @csrf
                                            @method('PATCH')
                                            <button type="submit" class="btn btn-sm">
                                                {{ $client->is_active ? 'Disabilita' : 'Abilita' }}
                                            </button>
                                        </form>

                                        <a href="{{ route('center-auth.panel.clients.edit', $client) }}" class="btn btn-sm">Modifica</a>

                                        <form method="POST" action="{{ route('center-auth.panel.clients.destroy', $client) }}"
                                              onsubmit="return confirm('Eliminare definitivamente l\'applicazione {{ addslashes($client->name) }}?');">
                                            @csrf
                                            @method('DELETE')
                                            <button type="submit" class="btn btn-sm btn-danger">Elimina</button>
                                        </form>
                                    </div>
                                </td>
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>
        @endif
    </div>

    <script>
        function copyText(elementId, button) {
            const el = document.getElementById(elementId);
            if (!el || !navigator.clipboard) return;
            navigator.clipboard.writeText(el.textContent.trim()).then(function () {
                const original = button.textContent;
                button.textContent = 'Copiato!';
                setTimeout(function () { button.textContent = original; }, 1800);
            });
        }
    </script>
@endsection
