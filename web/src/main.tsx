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
  overloaded: number;
  refused: number;
  rate_limited: number;
  rate_qps: number;
  rate_burst: number;
  local_records: number;
  local_answers: number;
  exceptions: number;
  upstream_mode: string;
  inbound_dot_enabled: boolean;
  rules: number;
};

function Console() {
  const [token, setToken] = useState('');
  const [status, setStatus] = useState<Status | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [domain, setDomain] = useState('');
  const [decision, setDecision] = useState<{name: string; decision: 'allowed' | 'blocked' | 'unmatched'} | null>(null);

  async function api(path: string, method: 'GET' | 'POST' = 'GET', payload?: object) {
    const response = await fetch(path, {
      method,
      headers: { Authorization: 'Bearer ' + token, ...(payload ? { 'Content-Type': 'application/json' } : {}) },
      ...(payload ? { body: JSON.stringify(payload) } : {}),
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

  async function reloadLocal() {
    setBusy(true);
    setMessage('');
    setError('');
    try {
      const result: { records: number } = await api('/api/v1/local/reload', 'POST');
      setStatus(await api('/api/v1/status'));
      setMessage('Loaded ' + result.records + ' local DNS records from the server configuration.');
    } catch (e) { setError(e instanceof Error ? e.message : 'Local DNS reload failed'); }
    finally { setBusy(false); }
  }

  async function checkDomain() {
    setBusy(true);
    setError('');
    setDecision(null);
    try {
      setDecision(await api('/api/v1/policy/check', 'POST', { name: domain.trim() }));
    } catch (e) { setError(e instanceof Error ? e.message : 'Policy check failed'); }
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
          <article className="metric"><span>Allow exceptions</span><strong>{status.exceptions.toLocaleString()}</strong><small>Override matching blocks</small></article>
          <article className="metric"><span>Overload refusals</span><strong>{status.overloaded.toLocaleString()}</strong><small>Upstream capacity protection</small></article>
          <article className="metric"><span>Clients refused</span><strong>{status.refused.toLocaleString()}</strong><small>Outside configured network ACL</small></article>
          <article className="metric"><span>Rate-limited queries</span><strong>{status.rate_limited.toLocaleString()}</strong><small>Global abuse protection</small></article>
          <article className="metric"><span>Local DNS records</span><strong>{status.local_records.toLocaleString()}</strong><small>Configured exact-name overrides</small></article>
          <article className="metric"><span>Local DNS answers</span><strong>{status.local_answers.toLocaleString()}</strong><small>Since process restart</small></article>
        </section>
        <section className="panel action-panel">
          <div><h2>Policy management</h2><p>Edit the rules file on your DNS host and reload it atomically. Invalid updates preserve the existing rules.</p></div>
          <button type="button" className="secondary" onClick={() => void reload()} disabled={busy}>Reload rules</button>
        </section>
        <section className="panel action-panel policy-check" aria-label="Local DNS records">
          <div><h2>Local DNS records</h2><p>Edit your A, AAAA, or CNAME overrides on the DNS host, then reload the entire validated file atomically. Invalid files keep the last working set.</p></div>
          <button className="secondary" type="button" disabled={busy} onClick={() => void reloadLocal()}>Reload local records</button>
        </section>
        <section className="panel policy-check" aria-label="Private domain policy check">
          <div><h2>Test a domain against policy</h2><p>Preview a local allow/block decision without sending a DNS query or saving a history. DNS may still fail upstream when no rule matches.</p></div>
          <form onSubmit={event => {event.preventDefault(); void checkDomain();}}>
            <label htmlFor="domain">Domain to check</label>
            <div className="input-row">
              <input id="domain" type="text" value={domain} maxLength={253} autoComplete="off" spellCheck={false} placeholder="example.org" onChange={event => {setDomain(event.target.value); setDecision(null);}} required />
              <button type="submit" disabled={busy || !domain.trim()}>Check policy</button>
            </div>
          </form>
          {decision && <p role="status" className="policy-result"><strong>{decision.name}</strong>: {decision.decision === 'blocked' ? 'blocked by local policy' : decision.decision === 'allowed' ? 'explicitly allowed by exception' : 'no local rule matched (forward upstream)'}</p>}
        </section>
        <p className="transport-note">Global DNS query budget: {status.rate_qps.toLocaleString()}/s, burst {status.rate_burst.toLocaleString()}.</p>
        <p className="transport-note">Inbound DNS-over-TLS: {status.inbound_dot_enabled ? "Enabled for configured client networks" : "Disabled"}</p>
        <p className="transport-note">Upstream transport: {status.upstream_mode === 'tls' ? 'DNS-over-TLS' : status.upstream_mode === 'tcp' ? 'DNS over TCP' : 'Client-appropriate UDP/TCP'}</p>
        <button className="disconnect" type="button" onClick={() => {setToken(''); setStatus(null); setDomain(''); setDecision(null); setError(''); setMessage('');}}>Disconnect and forget token</button>
      </> : <section className="empty"><h2>Ready when you are</h2><p>Connect locally or through a trusted HTTPS reverse proxy to see live aggregate metrics. Query histories and client IP addresses are not retained.</p></section>}
      <footer>GoreeCloud DNS · Self-hosted development software · No tracking or third-party analytics</footer>
    </main>
  );
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><Console /></React.StrictMode>);
