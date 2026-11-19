<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>@yield('title', 'CenterAuth — Applicazioni collegate')</title>
    <style>
        :root {
            color-scheme: light dark;
            --bg: #f8fafc;
            --surface: #ffffff;
            --surface-muted: #f1f5f9;
            --border: #e2e8f0;
            --text: #0f172a;
            --text-muted: #475569;
            --primary: #2563eb;
            --primary-hover: #1d4ed8;
            --success-bg: #dcfce7;
            --success-text: #166534;
            --danger: #dc2626;
            --danger-bg: #fee2e2;
            --danger-text: #991b1b;
            --warn-bg: #fef3c7;
            --warn-text: #92400e;
            --radius: 10px;
        }
        @media (prefers-color-scheme: dark) {
            :root {
                --bg: #0f172a;
                --surface: #1e293b;
                --surface-muted: #0b1220;
                --border: #334155;
                --text: #f1f5f9;
                --text-muted: #94a3b8;
                --primary: #3b82f6;
                --primary-hover: #2563eb;
                --success-bg: #14532d;
                --success-text: #bbf7d0;
                --danger: #ef4444;
                --danger-bg: #7f1d1d;
                --danger-text: #fecaca;
                --warn-bg: #78350f;
                --warn-text: #fde68a;
            }
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.5;
        }
        .container {
            max-width: 1120px;
            margin: 0 auto;
            padding: 2rem 1.25rem 3rem;
        }
        header.topbar {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            justify-content: space-between;
            gap: 1rem;
            margin-bottom: 1.75rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border);
        }
        .brand {
            display: flex;
            flex-direction: column;
            gap: 0.15rem;
        }
        .brand h1 {
            margin: 0;
            font-size: 1.35rem;
            font-weight: 700;
            letter-spacing: -0.01em;
        }
        .brand span {
            font-size: 0.875rem;
            color: var(--text-muted);
        }
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 1.25rem;
            margin-bottom: 1.25rem;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
            margin-bottom: 1.25rem;
        }
        .stat-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 1rem 1.25rem;
        }
        .stat-card .label { font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em; }
        .stat-card .value { font-size: 1.6rem; font-weight: 700; margin-top: 0.25rem; }
        .alert {
            border-radius: var(--radius);
            padding: 0.9rem 1.1rem;
            margin-bottom: 1.25rem;
            border: 1px solid transparent;
            font-size: 0.925rem;
        }
        .alert-success { background: var(--success-bg); color: var(--success-text); }
        .alert-warning { background: var(--warn-bg); color: var(--warn-text); }
        .alert-danger { background: var(--danger-bg); color: var(--danger-text); }
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 0.4rem;
            padding: 0.5rem 0.9rem;
            font-size: 0.875rem;
            font-weight: 600;
            border-radius: 7px;
            border: 1px solid var(--border);
            background: var(--surface);
            color: var(--text);
            text-decoration: none;
            cursor: pointer;
            transition: background 0.15s ease, border-color 0.15s ease;
        }
        .btn:hover { background: var(--surface-muted); }
        .btn:focus-visible { outline: 2px solid var(--primary); outline-offset: 2px; }
        .btn-primary {
            background: var(--primary);
            border-color: var(--primary);
            color: #ffffff;
        }
        .btn-primary:hover { background: var(--primary-hover); border-color: var(--primary-hover); }
        .btn-danger {
            color: var(--danger);
            border-color: var(--border);
        }
        .btn-danger:hover { background: var(--danger-bg); color: var(--danger-text); }
        .btn-sm { padding: 0.32rem 0.65rem; font-size: 0.8rem; }
        .badge {
            display: inline-flex;
            align-items: center;
            gap: 0.35rem;
            padding: 0.2rem 0.6rem;
            border-radius: 999px;
            font-size: 0.78rem;
            font-weight: 600;
        }
        .badge-active { background: var(--success-bg); color: var(--success-text); }
        .badge-disabled { background: var(--danger-bg); color: var(--danger-text); }
        .badge-warn { background: var(--warn-bg); color: var(--warn-text); }
        .table-wrap {
            width: 100%;
            overflow-x: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }
        th, td {
            text-align: left;
            padding: 0.85rem 0.75rem;
            border-bottom: 1px solid var(--border);
            vertical-align: middle;
        }
        th {
            font-size: 0.78rem;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            color: var(--text-muted);
            font-weight: 600;
        }
        tr:last-child td { border-bottom: none; }
        .actions {
            display: flex;
            flex-wrap: wrap;
            gap: 0.4rem;
            align-items: center;
        }
        .actions form { margin: 0; }
        code, pre {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.84rem;
        }
        code {
            background: var(--surface-muted);
            padding: 0.15rem 0.4rem;
            border-radius: 5px;
        }
        pre {
            background: var(--surface-muted);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 0.85rem 1rem;
            overflow-x: auto;
            margin: 0.6rem 0 0;
        }
        .form-group { margin-bottom: 1rem; }
        .form-group label {
            display: block;
            font-weight: 600;
            font-size: 0.875rem;
            margin-bottom: 0.35rem;
        }
        .form-control {
            width: 100%;
            padding: 0.55rem 0.75rem;
            border: 1px solid var(--border);
            border-radius: 7px;
            background: var(--surface);
            color: var(--text);
            font-size: 0.925rem;
        }
        .form-control:focus { outline: 2px solid var(--primary); outline-offset: 1px; border-color: var(--primary); }
        .help { font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem; }
        .error-text { font-size: 0.82rem; color: var(--danger); margin-top: 0.25rem; }
        .checkbox-row {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .checkbox-row input[type="checkbox"] {
            width: 1rem;
            height: 1rem;
            accent-color: var(--primary);
        }
        .muted { color: var(--text-muted); font-size: 0.84rem; }
    </style>
</head>
<body>
    <div class="container">
        <header class="topbar">
            <div class="brand">
                <h1>CenterAuth — Applicazioni collegate</h1>
                <span>Gestione centralizzata dei client SSO autorizzati</span>
            </div>
            <div>
                @yield('header-actions')
            </div>
        </header>

        @if (session('status'))
            <div class="alert alert-success" role="status">
                {{ session('status') }}
            </div>
        @endif

        @yield('content')
    </div>
</body>
</html>
