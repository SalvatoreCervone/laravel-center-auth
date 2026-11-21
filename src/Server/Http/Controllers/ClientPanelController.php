<?php

namespace CenterAuth\Server\Http\Controllers;

use CenterAuth\Models\CenterAuthClient;
use Illuminate\Database\QueryException;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\Rule;
use Illuminate\View\View;

class ClientPanelController extends Controller
{
    public function index(): View
    {
        try {
            $clients = CenterAuthClient::query()
                ->orderByDesc('is_active')
                ->orderBy('name')
                ->get();
        } catch (QueryException) {
            $clients = collect();
        }

        return view('center-auth::panel.index', [
            'clients' => $clients,
            'driver' => (string) config('center-auth.server.client_driver', 'config'),
            'issuer' => rtrim((string) config('center-auth.server.issuer', config('app.url')), '/'),
            'routePrefix' => trim((string) config('center-auth.route_prefix', 'center-auth'), '/'),
            'defaultGraceHours' => (int) config('center-auth.server.panel.secret_rotation_grace_hours', 24),
        ]);
    }

    public function create(): View
    {
        return view('center-auth::panel.form', [
            'client' => new CenterAuthClient(['is_active' => true]),
            'isEdit' => false,
            'defaultGraceHours' => (int) config('center-auth.server.panel.secret_rotation_grace_hours', 24),
        ]);
    }

    public function store(Request $request): RedirectResponse
    {
        $validated = $request->validate([
            'name' => ['required', 'string', 'max:120'],
            'client_id' => ['required', 'string', 'max:80', 'regex:/^[a-z0-9][a-z0-9_-]*$/', 'unique:center_auth_clients,client_id'],
            'callback_url' => ['required', 'url:http,https', 'max:255'],
            'description' => ['nullable', 'string', 'max:500'],
            'is_active' => ['nullable', 'boolean'],
        ]);

        $plainSecret = CenterAuthClient::generateSecret();

        $client = CenterAuthClient::create([
            'name' => $validated['name'],
            'client_id' => $validated['client_id'],
            'callback_url' => $validated['callback_url'],
            'description' => $validated['description'] ?? null,
            'is_active' => $request->boolean('is_active', true),
            'secret_hash' => Hash::make($plainSecret),
        ]);

        return redirect()
            ->route('center-auth.panel.index')
            ->with('status', "Applicazione \"{$client->name}\" creata con successo.")
            ->with('generated_client_id', $client->client_id)
            ->with('generated_secret', $plainSecret);
    }

    public function edit(CenterAuthClient $client): View
    {
        return view('center-auth::panel.form', [
            'client' => $client,
            'isEdit' => true,
            'defaultGraceHours' => (int) config('center-auth.server.panel.secret_rotation_grace_hours', 24),
        ]);
    }

    public function update(Request $request, CenterAuthClient $client): RedirectResponse
    {
        $validated = $request->validate([
            'name' => ['required', 'string', 'max:120'],
            'client_id' => [
                'required',
                'string',
                'max:80',
                'regex:/^[a-z0-9][a-z0-9_-]*$/',
                Rule::unique('center_auth_clients', 'client_id')->ignore($client->id),
            ],
            'callback_url' => ['required', 'url:http,https', 'max:255'],
            'description' => ['nullable', 'string', 'max:500'],
            'is_active' => ['nullable', 'boolean'],
        ]);

        $client->update([
            'name' => $validated['name'],
            'client_id' => $validated['client_id'],
            'callback_url' => $validated['callback_url'],
            'description' => $validated['description'] ?? null,
            'is_active' => $request->boolean('is_active', false),
        ]);

        return redirect()
            ->route('center-auth.panel.index')
            ->with('status', "Applicazione \"{$client->name}\" aggiornata.");
    }

    public function toggle(CenterAuthClient $client): RedirectResponse
    {
        $client->is_active = ! $client->is_active;
        $client->save();

        $state = $client->is_active ? 'abilitata' : 'disabilitata';

        return redirect()
            ->route('center-auth.panel.index')
            ->with('status', "Applicazione \"{$client->name}\" {$state}.");
    }

    public function rotateSecret(Request $request, CenterAuthClient $client): RedirectResponse
    {
        $defaultGrace = (int) config('center-auth.server.panel.secret_rotation_grace_hours', 24);

        $validated = $request->validate([
            'grace_hours' => ['nullable', 'integer', 'min:0', 'max:720'],
        ]);

        $graceHours = array_key_exists('grace_hours', $validated) && $validated['grace_hours'] !== null
            ? (int) $validated['grace_hours']
            : $defaultGrace;

        $newPlainSecret = $client->rotateSecret($graceHours);

        $graceText = $graceHours > 0
            ? "Il vecchio secret resterà valido per {$graceHours} ore."
            : 'Il vecchio secret è stato invalidato immediatamente.';

        return redirect()
            ->route('center-auth.panel.index')
            ->with('status', "Secret ruotato per \"{$client->name}\". {$graceText}")
            ->with('generated_client_id', $client->client_id)
            ->with('generated_secret', $newPlainSecret);
    }

    public function destroy(CenterAuthClient $client): RedirectResponse
    {
        $name = $client->name;
        $client->delete();

        return redirect()
            ->route('center-auth.panel.index')
            ->with('status', "Applicazione \"{$name}\" eliminata.");
    }
}
