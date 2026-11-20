import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';
import './gc-tokens.css';
import './styles.css';

type Status = {
  product: string;
  state: string;
  queries: number;
  blocked: number;
  upstream_errors: number;
  rules: number;
};

function Console() {
  const [token, setToken] = useState('');
  const [status, setStatus] = useState<Status | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  async function api(path: string, method: 'GET' | 'POST' = 'GET') {
    const response = await fetch(path, {
      method,
      headers: { Authorization: 'Bearer ' + token },
      cache: 'no-store',
      credentials: 'omit',
      referrerPolicy: 'no-referrer'
    });
    if (!response.ok) {
      throw new Error(response.status === 401 ? 'Incorrect API token' : 'Request failed (' + response.status + ')');
    }
    return response.json();
  }

  async function connect() {
    setBusy(true);
    setMessage('');
    setError('');
    try { setStatus(await api('/api/v1/status')); }
    catch (e) { setStatus(null); setError(e instanceof Error ? e.message : 'Connection failed'); }
    finally { setBusy(false); }
  }

  async function reload() {
    setBusy(true);
    setMessage('');
    setError('');
    try {
      const result: { rules: number } = await api('/api/v1/rules/reload', 'POST');
      setStatus(await api('/api/v1/status'));
      setMessage('Loaded ' + result.rules + ' rules from the server configuration.');
    } catch (e) { setError(e instanceof Error ? e.message : 'Reload failed'); }
    finally { setBusy(false); }
  }

  return (
    <main className="layout">
      <header className="topbar">
        <div><strong>GoreeCloud DNS</strong><span>Private network control</span></div>
        <span className="environment">Development preview</span>
      </header>
      <section className="intro">
        <p className="eyebrow">DNS MANAGEMENT</p>
        <h1>Know what your network resolves.</h1>
        <p>Run your own DNS filtering gateway, keep query data private, and control your local resolver.</p>
      </section>
      <section className="panel connection" aria-label="Connection settings">
        <div><h2>Connect to your DNS server</h2><p>Use the API token configured on your self-hosted instance. It remains only in this page's memory.</p></div>
        <form onSubmit={event => {event.preventDefault(); void connect();}}>
          <label htmlFor="token">API token</label>
          <div className="input-row">
            <input id="token" type="password" autoComplete="off" spellCheck={false} placeholder="Paste your token" value={token} onChange={e => setToken(e.target.value)} required minLength={16}/>
            <button type="submit" disabled={busy || token.length < 16}>{busy ? 'Working…' : status ? 'Refresh' : 'Connect'}</button>
          </div>
        </form>
      </section>
      {error && <p className="feedback error" role="alert">{error}</p>}
      {message && <p className="feedback success" role="status">{message}</p>}
      {status ? <>
        <section className="metrics" aria-label="Resolver metrics">
          <article className="metric"><span>Total queries</span><strong>{status.queries.toLocaleString()}</strong><small>Since process start</small></article>
          <article className="metric"><span>Blocked queries</span><strong>{status.blocked.toLocaleString()}</strong><small>Policy decisions</small></article>
          <article className="metric"><span>Upstream errors</span><strong>{status.upstream_errors.toLocaleString()}</strong><small>Resolver failures</small></article>
          <article className="metric"><span>Active rules</span><strong>{status.rules.toLocaleString()}</strong><small>Domain suffix policies</small></article>
        </section>
        <section className="panel action-panel">
          <div><h2>Policy management</h2><p>Edit the rules file on your DNS host and reload it atomically. Invalid updates preserve the existing rules.</p></div>
          <button type="button" className="secondary" onClick={() => void reload()} disabled={busy}>Reload rules</button>
        </section>
        <button className="disconnect" type="button" onClick={() => {setToken(''); setStatus(null); setError(''); setMessage('');}}>Disconnect and forget token</button>
      </> : <section className="empty"><h2>Ready when you are</h2><p>Connect locally or through a trusted HTTPS reverse proxy to see live aggregate metrics. Query histories and client IP addresses are not retained.</p></section>}
      <footer>GoreeCloud DNS · Self-hosted development software · No tracking or third-party analytics</footer>
    </main>
  );
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><Console /></React.StrictMode>);
