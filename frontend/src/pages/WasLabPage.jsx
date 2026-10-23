import React, { useState } from 'react';
import { wasLabAPI } from '../services/api';
import {
  ShieldAlert, ShieldCheck, Code2, Eye, Zap,
  AlertTriangle, CheckCircle2, XCircle, Loader2,
  ChevronDown, ChevronRight, ArrowUpRight, Send,
  Terminal, Lock, User, List
} from 'lucide-react';

// ─── Shared palette ──────────────────────────────────────────────────────────

const C = {
  red:    { bg: 'bg-red-500/10',    border: 'border-red-500/30',    text: 'text-red-400',    badge: 'bg-red-500/20 text-red-300',    btn: 'hover:bg-red-500/20 border-red-500/40 text-red-300' },
  orange: { bg: 'bg-orange-500/10', border: 'border-orange-500/30', text: 'text-orange-400', badge: 'bg-orange-500/20 text-orange-300', btn: 'hover:bg-orange-500/20 border-orange-500/40 text-orange-300' },
  yellow: { bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', text: 'text-yellow-400', badge: 'bg-yellow-500/20 text-yellow-300', btn: 'hover:bg-yellow-500/20 border-yellow-500/40 text-yellow-300' },
  purple: { bg: 'bg-purple-500/10', border: 'border-purple-500/30', text: 'text-purple-400', badge: 'bg-purple-500/20 text-purple-300', btn: 'hover:bg-purple-500/20 border-purple-500/40 text-purple-300' },
  cyan:   { bg: 'bg-cyan-500/10',   border: 'border-cyan-500/30',   text: 'text-cyan-400',   badge: 'bg-cyan-500/20 text-cyan-300',   btn: 'hover:bg-cyan-500/20 border-cyan-500/40 text-cyan-300' },
};

// ─── HTTP Timeline ────────────────────────────────────────────────────────────

function StatusChip({ code }) {
  const color = code >= 500 ? 'text-red-400 bg-red-500/20' :
                code === 429 ? 'text-orange-400 bg-orange-500/20' :
                code === 403 ? 'text-yellow-400 bg-yellow-500/20' :
                code === 401 ? 'text-purple-400 bg-purple-500/20' :
                code === 200 ? 'text-emerald-400 bg-emerald-500/20' :
                'text-slate-300 bg-slate-700';
  return (
    <span className={`font-mono text-xs px-2 py-0.5 rounded-full font-bold ${color}`}>{code}</span>
  );
}

function MethodBadge({ method }) {
  const color = method === 'POST' ? 'text-emerald-300 bg-emerald-500/10' :
                method === 'GET'  ? 'text-cyan-300 bg-cyan-500/10' :
                method === 'SCAN' ? 'text-yellow-300 bg-yellow-500/10' :
                method === 'RENDER' ? 'text-purple-300 bg-purple-500/10' :
                'text-slate-300 bg-slate-700';
  return (
    <span className={`font-mono text-[10px] px-1.5 py-0.5 rounded font-bold uppercase ${color}`}>{method}</span>
  );
}

function HttpTimeline({ steps }) {
  if (!steps?.length) return null;
  return (
    <div className="space-y-2 mt-3">
      <p className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider flex items-center gap-1.5">
        <Terminal className="w-3 h-3" /> Live HTTP Trace
      </p>
      <div className="space-y-1.5">
        {steps.map((s, i) => (
          <div key={i} className="bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-[11px] space-y-1">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 min-w-0">
                <MethodBadge method={s.method} />
                <span className="text-slate-400 truncate">{s.endpoint}</span>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <StatusChip code={s.status} />
                <span className="text-slate-600 text-[10px]">{s.timestamp}</span>
              </div>
            </div>
            {(s.request_data !== undefined || s.request_summary) && (
              <p className="text-slate-500 pl-1 border-l-2 border-slate-800">
                REQ: <span className="text-slate-400 break-all">
                  {typeof s.request_data === 'string'
                    ? s.request_data
                    : JSON.stringify(s.request_data ?? s.request_summary)}
                </span>
              </p>
            )}
            {(s.response_body !== undefined || s.response_snippet) && (
              <div className="text-slate-500 pl-1 border-l-2 border-slate-700">
                <span>RES: </span>
                <pre className={`inline whitespace-pre-wrap break-all ${s.status === 429 ? 'text-orange-300' : s.status === 403 ? 'text-yellow-300' : 'text-slate-300'}`}>
                  {typeof s.response_body === 'string'
                    ? s.response_body
                    : JSON.stringify(s.response_body ?? s.response_snippet)}
                </pre>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Result Banner ────────────────────────────────────────────────────────────

function ResultBanner({ result, alert_id, alert_url, security_control, detection_method, extra }) {
  const prevented = result === 'PREVENTED';
  const authorized = result === 'AUTHORIZED';
  return (
    <div className={`rounded-xl border p-4 space-y-2 text-xs mt-3 ${prevented || authorized ? 'bg-emerald-950/40 border-emerald-500/20' : 'bg-amber-950/40 border-amber-500/30'}`}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {prevented || authorized
            ? <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            : <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />}
          <span className={`font-bold text-sm ${prevented || authorized ? 'text-emerald-300' : 'text-amber-300'}`}>
            {prevented ? 'ATTACK PREVENTED' : authorized ? 'AUTHORIZED ADMIN ACCESS' : result}
          </span>
        </div>
        {alert_id && (
          <a href={alert_url || '/alerts'} aria-label={`Open alert ${alert_id}`} className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300 font-mono text-[11px] hover:underline">
            {alert_id} <ArrowUpRight className="w-3 h-3" />
          </a>
        )}
      </div>
      <div className="space-y-1 text-slate-400">
        <p><span className="text-slate-500">Security Control: </span><span className="text-slate-200">{security_control}</span></p>
        <p><span className="text-slate-500">Detection: </span><span className="text-slate-300">{detection_method}</span></p>
        {alert_id && <p><span className="text-slate-500">Security Event ID: </span><span className="font-mono text-cyan-300">{alert_id}</span></p>}
        {alert_id && <p className="text-slate-500">Open this SOC alert to acknowledge it or convert it to an incident for analyst investigation.</p>}
        {extra?.rows_returned !== undefined && (
          <p><span className="text-slate-500">SQLi rows returned: </span>
            <span className="text-emerald-400">{extra.rows_returned}/{extra.total_employees} — injection {extra.injection_successful ? 'SUCCEEDED ⚠️' : 'FAILED ✓'}</span></p>
        )}
        {extra?.sqli_patterns_detected?.length > 0 && (
          <p><span className="text-slate-500">Patterns flagged: </span>
            <span className="text-yellow-300">{extra.sqli_patterns_detected.length} pattern(s) detected by input scanner</span></p>
        )}
        {extra?.stored_as_literal_text !== undefined && (
          <p><span className="text-slate-500">Stored safely: </span>
            <span className="text-emerald-400">{extra.stored_as_literal_text ? 'Yes — plain text' : 'No'}</span>
            {extra.html_escaped_equivalent && <span className="text-slate-500 ml-2">→ html.escape: </span>}
            {extra.html_escaped_equivalent && <span className="text-slate-300 break-all">{extra.html_escaped_equivalent?.slice(0, 80)}</span>}
          </p>
        )}
        {extra?.rate_limited !== undefined && (
          <p><span className="text-slate-500">Rate limited: </span>
            <span className={extra.rate_limited ? 'text-emerald-400' : 'text-amber-400'}>
              {extra.rate_limited ? `Yes — at request #${extra.hit_429_at_request}` : `No — ${extra.requests_sent} requests sent`}
            </span></p>
        )}
        {extra?.access_granted !== undefined && (
          <p><span className="text-slate-500">Access granted: </span>
            <span className={extra.access_granted ? 'text-red-400' : 'text-emerald-400'}>
              {extra.access_granted ? 'YES — VULNERABILITY' : 'No — blocked by RBAC ✓'}
            </span></p>
        )}
      </div>
    </div>
  );
}

// ─── Error Box ────────────────────────────────────────────────────────────────

function ErrorBox({ msg }) {
  return (
    <div className="mt-3 bg-red-950/50 border border-red-500/30 rounded-xl p-3 text-xs flex items-start gap-2">
      <XCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
      <span className="text-red-300 font-mono">{msg}</span>
    </div>
  );
}

// ─── Input helpers ────────────────────────────────────────────────────────────

const inputCls = "w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono placeholder:text-slate-600 focus:outline-none focus:border-slate-500";
const labelCls = "text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-1 block";

// ─── Panel A: Brute Force ─────────────────────────────────────────────────────

function BruteForcePanel() {
  const [passwords, setPasswords] = useState("wrongpass1\nwrongpass2\nwrongpass3\nwrongpass4\nwrongpass5\nwrongpass6");
  const [state, setState] = useState('idle');
  const [result, setResult] = useState(null);
  const [err, setErr] = useState('');

  const run = async () => {
    const list = passwords.split('\n').map(s => s.trim()).filter(Boolean);
    if (!list.length) {
      setResult(null);
      setErr('Enter at least one incorrect password to run the test.');
      setState('error');
      return;
    }
    if (list.length > 8) {
      setResult(null);
      setErr('A maximum of 8 password attempts is allowed per run.');
      setState('error');
      return;
    }
    setState('loading'); setResult(null); setErr('');
    try {
      const res = await wasLabAPI.interactiveBruteForce(list);
      setResult(res.data); setState('success');
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message || 'Error'); setState('error');
    }
  };

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3 text-[11px]">
        <div className="bg-slate-900/60 rounded-lg p-3 border border-slate-800">
          <p className="text-slate-500 font-semibold mb-1">TARGET ACCOUNT</p>
          <p className="text-slate-300 font-mono">was-interactive-bf@soc.corp</p>
          <p className="text-slate-600 mt-1">Dedicated low-privilege lab account; no human account is targeted</p>
        </div>
        <div className="bg-slate-900/60 rounded-lg p-3 border border-slate-800">
          <p className="text-slate-500 font-semibold mb-1">RATE LIMIT</p>
          <p className="text-slate-300 font-mono">5 requests / minute per IP</p>
          <p className="text-slate-600 mt-1">Enforced by slowapi on /auth/login</p>
        </div>
      </div>
      <div>
        <label className={labelCls}>Password attempts (one per line, max 8)</label>
        <textarea
          className={`${inputCls} resize-none h-36`}
          value={passwords}
          onChange={e => setPasswords(e.target.value)}
          placeholder="wrongpassword1&#10;wrongpassword2&#10;..."
        />
        <p className="text-[10px] text-slate-600 mt-1">
          {passwords.split('\n').filter(Boolean).length} attempt(s) queued — the sixth request exceeds the five-request limit
        </p>
      </div>
      {result && <HttpTimeline steps={result.steps} />}
      {result && <ResultBanner {...result} extra={result} />}
      {err && <ErrorBox msg={err} />}
      <button onClick={run} disabled={state === 'loading'} className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold border transition-all ${state === 'loading' ? 'bg-slate-800 border-slate-700 text-slate-500 cursor-not-allowed' : 'bg-red-500/10 border-red-500/40 text-red-300 hover:bg-red-500/20'}`}>
        {state === 'loading' ? <Loader2 className="w-3 h-3 animate-spin" /> : <Send className="w-3 h-3" />}
        {state === 'loading' ? 'Attacking…' : 'Start Brute-Force Attack'}
      </button>
    </div>
  );
}

// ─── Panel B: Broken Access Control ──────────────────────────────────────────

const ALLOWED_ENDPOINTS = [
  '/api/v1/admin/audit-logs',
  '/api/v1/reports/threat/csv',
  '/api/v1/reports/risk/excel',
];
const ALLOWED_ROLES = ['Security Analyst', 'Administrator'];

function BrokenAccessPanel() {
  const [role, setRole] = useState('Security Analyst');
  const [endpoint, setEndpoint] = useState('/api/v1/admin/audit-logs');
  const [state, setState] = useState('idle');
  const [result, setResult] = useState(null);
  const [err, setErr] = useState('');

  const run = async () => {
    setState('loading'); setResult(null); setErr('');
    try {
      const res = await wasLabAPI.interactiveBrokenAccess(role, endpoint);
      setResult(res.data); setState('success');
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message || 'Error'); setState('error');
    }
  };

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className={labelCls}><User className="inline w-3 h-3 mr-1" />Test Identity (role)</label>
          <select value={role} onChange={e => setRole(e.target.value)} className={inputCls}>
            {ALLOWED_ROLES.map(r => <option key={r} value={r}>{r}</option>)}
          </select>
        </div>
        <div>
          <label className={labelCls}><Lock className="inline w-3 h-3 mr-1" />Target endpoint (admin-only)</label>
          <select value={endpoint} onChange={e => setEndpoint(e.target.value)} className={inputCls}>
            {ALLOWED_ENDPOINTS.map(e => <option key={e} value={e}>{e}</option>)}
          </select>
        </div>
      </div>
      <div className="bg-slate-900/60 rounded-lg p-3 border border-slate-800 text-[11px] text-slate-400">
        A real backend-issued token for <span className="text-slate-200 font-mono">{role}</span> will call the allowlisted, read-only endpoint <span className="text-slate-200 font-mono">{endpoint}</span>. Analyst access should receive 403; Administrator access should receive 200.
      </div>
      {result && <HttpTimeline steps={result.steps} />}
      {result && <ResultBanner {...result} extra={result} />}
      {err && <ErrorBox msg={err} />}
      <button onClick={run} disabled={state === 'loading'} className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold border transition-all ${state === 'loading' ? 'bg-slate-800 border-slate-700 text-slate-500 cursor-not-allowed' : 'bg-orange-500/10 border-orange-500/40 text-orange-300 hover:bg-orange-500/20'}`}>
        {state === 'loading' ? <Loader2 className="w-3 h-3 animate-spin" /> : <Send className="w-3 h-3" />}
        {state === 'loading' ? 'Testing…' : 'Test Access Control'}
      </button>
    </div>
  );
}

// ─── Panel C: SQL Injection ───────────────────────────────────────────────────

const SQLI_PRESETS = [
  { label: "Classic OR bypass",      value: "' OR '1'='1" },
  { label: "DROP TABLE attempt",      value: "'; DROP TABLE employees; --" },
  { label: "UNION SELECT",            value: "' UNION SELECT * FROM users--" },
  { label: "Comment bypass",          value: "admin'--" },
  { label: "Normal search (control)", value: "Alice" },
];

function SqlInjectionPanel() {
  const [input, setInput] = useState("' OR '1'='1");
  const [state, setState] = useState('idle');
  const [result, setResult] = useState(null);
  const [err, setErr] = useState('');

  const run = async () => {
    setState('loading'); setResult(null); setErr('');
    try {
      const res = await wasLabAPI.interactiveSqlInjection(input);
      setResult(res.data); setState('success');
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message || 'Error'); setState('error');
    }
  };

  return (
    <div className="space-y-3">
      <div>
        <label className={labelCls}>Preset payloads</label>
        <div className="flex flex-wrap gap-2">
          {SQLI_PRESETS.map(p => (
            <button key={p.value} onClick={() => setInput(p.value)}
              className="px-2 py-1 rounded-lg bg-slate-800 border border-slate-700 text-[10px] text-slate-400 hover:text-slate-200 hover:border-slate-600 font-mono transition-colors">
              {p.label}
            </button>
          ))}
        </div>
      </div>
      <div>
        <label className={labelCls}>Employee search input (your SQL injection payload)</label>
        <input type="text" className={inputCls} value={input} onChange={e => setInput(e.target.value)}
          placeholder="Enter any search term or SQLi payload..." maxLength={200} />
        <p className="text-[10px] text-slate-600 mt-1">
          Sent as: <span className="font-mono">SELECT ... WHERE name ILIKE %?%</span> — always parameterized by SQLAlchemy ORM
        </p>
      </div>
      {result && <HttpTimeline steps={result.steps} />}
      {result && <ResultBanner {...result} extra={result} />}
      {err && <ErrorBox msg={err} />}
      <button onClick={run} disabled={state === 'loading'} className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold border transition-all ${state === 'loading' ? 'bg-slate-800 border-slate-700 text-slate-500 cursor-not-allowed' : 'bg-yellow-500/10 border-yellow-500/40 text-yellow-300 hover:bg-yellow-500/20'}`}>
        {state === 'loading' ? <Loader2 className="w-3 h-3 animate-spin" /> : <Send className="w-3 h-3" />}
        {state === 'loading' ? 'Injecting…' : 'Run SQL Injection Test'}
      </button>
    </div>
  );
}

// ─── Panel D: XSS Prevention ─────────────────────────────────────────────────

const XSS_PRESETS = [
  { label: "<script> marker",   value: "<script>document.body.dataset.wasXss='executed'</script>" },
  { label: "img onerror marker", value: "<img src=x onerror=\"document.body.dataset.wasXss='executed'\">" },
  { label: "SVG marker",        value: "<svg onload=\"document.body.dataset.wasXss='executed'\"></svg>" },
  { label: "Plain text (safe)",  value: "Normal investigation note — no attack here" },
];

function XssPrevPanel() {
  const [content, setContent] = useState("<script>alert('XSS Attack!')</script>");
  const [state, setState] = useState('idle');
  const [result, setResult] = useState(null);
  const [err, setErr] = useState('');

  const run = async () => {
    setState('loading'); setResult(null); setErr('');
    try {
      const res = await wasLabAPI.interactiveXss(content);
      setResult(res.data); setState('success');
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message || 'Error'); setState('error');
    }
  };

  return (
    <div className="space-y-3">
      <div>
        <label className={labelCls}>Preset payloads</label>
        <div className="flex flex-wrap gap-2">
          {XSS_PRESETS.map(p => (
            <button key={p.label} onClick={() => setContent(p.value)}
              className="px-2 py-1 rounded-lg bg-slate-800 border border-slate-700 text-[10px] text-slate-400 hover:text-slate-200 hover:border-slate-600 font-mono transition-colors">
              {p.label}
            </button>
          ))}
        </div>
      </div>
      <div>
        <label className={labelCls}>Investigation note content (enter XSS payload)</label>
        <textarea className={`${inputCls} resize-none h-24`} value={content}
          onChange={e => setContent(e.target.value)} maxLength={500}
          placeholder="<script>alert('xss')</script>" />
      </div>
      {result && (
        <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-3 text-[11px] font-mono space-y-1.5">
          <p className="text-slate-500 font-semibold text-[10px] uppercase mb-2">React Rendering Demo</p>
          <p className="text-slate-500">Submitted: <span className="text-slate-300 break-all">{result.submitted_content?.slice(0, 80)}</span></p>
          <p className="text-slate-500">DB stored: <span className="text-slate-300 break-all">{result.stored_value?.slice(0, 80)}</span></p>
          <p className="text-slate-500">html.escape: <span className="text-emerald-300 break-all">{result.html_escaped_equivalent?.slice(0, 80)}</span></p>
          <div className="mt-2 p-2 bg-slate-950 rounded border border-slate-700">
            <p className="text-slate-600 text-[10px] mb-1">React renders the stored value as (text node — no execution):</p>
            {/* This is the actual JSX rendering — React auto-escapes this */}
            <p data-testid="xss-rendered-content" className="text-slate-200 break-all">{result.stored_value}</p>
          </div>
          <p className="text-emerald-400">Stored content retrieved from isolated WAS record and rendered as React text.</p>
        </div>
      )}
      {result && <HttpTimeline steps={result.steps} />}
      {result && <ResultBanner {...result} extra={result} />}
      {err && <ErrorBox msg={err} />}
      <button onClick={run} disabled={state === 'loading'} className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold border transition-all ${state === 'loading' ? 'bg-slate-800 border-slate-700 text-slate-500 cursor-not-allowed' : 'bg-purple-500/10 border-purple-500/40 text-purple-300 hover:bg-purple-500/20'}`}>
        {state === 'loading' ? <Loader2 className="w-3 h-3 animate-spin" /> : <Send className="w-3 h-3" />}
        {state === 'loading' ? 'Injecting…' : 'Test XSS Prevention'}
      </button>
    </div>
  );
}

// ─── Panel E: API Rate Limiting ───────────────────────────────────────────────

function RateLimitPanel() {
  const [count, setCount] = useState(12);
  const [endpoint, setEndpoint] = useState('/api/v1/was/lab/rate-limit-target');
  const [state, setState] = useState('idle');
  const [result, setResult] = useState(null);
  const [err, setErr] = useState('');

  const run = async () => {
    setState('loading'); setResult(null); setErr('');
    try {
      const res = await wasLabAPI.interactiveRateLimit(count, endpoint);
      setResult(res.data); setState('success');
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message || 'Error'); setState('error');
    }
  };

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3 text-[11px]">
        <div>
          <label className={labelCls}>Allowlisted lab endpoint</label>
          <select value={endpoint} onChange={e => setEndpoint(e.target.value)} className={inputCls}>
            <option value="/api/v1/was/lab/rate-limit-target">GET /was/lab/rate-limit-target</option>
            <option value="/api/v1/was/lab/rate-limit-target/ping">GET /was/lab/rate-limit-target/ping</option>
          </select>
          <p className="text-slate-600 mt-1">Isolated limit: 10 requests / minute</p>
        </div>
        <div className="bg-slate-900/60 rounded-lg p-3 border border-slate-800">
          <p className="text-slate-500 font-semibold mb-1">IDENTITY</p>
          <p className="text-slate-300 font-mono">Administrator lab token</p>
          <p className="text-slate-600 mt-1">Backend-issued and restricted to isolated lab routes</p>
        </div>
      </div>
      <div>
        <label className={labelCls}>
          <List className="inline w-3 h-3 mr-1" />
          Number of requests to fire: <span className="text-cyan-400 ml-1">{count}</span>
        </label>
        <input type="range" min={1} max={15} value={count} onChange={e => setCount(+e.target.value)}
          className="w-full accent-cyan-400 mt-1" />
        <div className="flex justify-between text-[10px] text-slate-600 mt-0.5">
          <span>1 (safe)</span>
          <span className="text-orange-400">10 = limit</span>
          <span className="text-red-400">15 (max)</span>
        </div>
        <p className="text-[10px] text-slate-600 mt-1">
          {count <= 10 ? `${count} requests — may not trigger 429 (limit is 10/min)` : `${count} sequential requests — expected HTTP 429 after the 10-request limit`}
        </p>
      </div>
      {result && <HttpTimeline steps={result.steps} />}
      {result && <ResultBanner {...result} extra={result} />}
      {err && <ErrorBox msg={err} />}
      <button onClick={run} disabled={state === 'loading'} className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold border transition-all ${state === 'loading' ? 'bg-slate-800 border-slate-700 text-slate-500 cursor-not-allowed' : 'bg-cyan-500/10 border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/20'}`}>
        {state === 'loading' ? <Loader2 className="w-3 h-3 animate-spin" /> : <Send className="w-3 h-3" />}
        {state === 'loading' ? `Firing ${count} requests…` : `Fire ${count} Requests`}
      </button>
    </div>
  );
}

// ─── Accordion Panel ──────────────────────────────────────────────────────────

const PANELS = [
  {
    id: 'brute-force',
    title: 'Brute-Force Login Protection',
    owasp: 'OWASP A07:2021',
    color: 'red',
    Icon: ShieldAlert,
    concept: 'An attacker submits multiple incorrect passwords hoping to guess valid credentials. The rate limiter detects the burst and blocks further attempts.',
    attack: '6+ failed /auth/login attempts from same IP',
    defense: 'slowapi rate limiter — 5 requests/minute per IP → HTTP 429',
    Component: BruteForcePanel,
  },
  {
    id: 'broken-access',
    title: 'Broken Access Control',
    owasp: 'OWASP A01:2021',
    color: 'orange',
    Icon: ShieldCheck,
    concept: 'A low-privilege user obtains a JWT and uses it to call an Administrator-only endpoint, attempting privilege escalation. RBAC blocks it server-side.',
    attack: 'Analyst/Manager JWT token calling admin-only endpoint',
    defense: 'require_roles() FastAPI dependency — server-side role check → HTTP 403',
    Component: BrokenAccessPanel,
  },
  {
    id: 'sql-injection',
    title: 'SQL Injection Prevention',
    owasp: 'OWASP A03:2021',
    color: 'yellow',
    Icon: Code2,
    concept: "SQL injection appends malicious SQL to a query hoping to bypass logic or exfiltrate data. SQLAlchemy's ORM always parameterizes inputs — payload is treated as literal text.",
    attack: "' OR '1'='1 / DROP TABLE / UNION SELECT payloads",
    defense: "SQLAlchemy ORM parameterized queries + regex input scanner",
    Component: SqlInjectionPanel,
  },
  {
    id: 'xss-prevention',
    title: 'XSS Prevention',
    owasp: 'OWASP A03:2021 (XSS)',
    color: 'purple',
    Icon: Eye,
    concept: 'A stored XSS attack embeds script tags in user content hoping they execute when displayed. React JSX renders all values as text nodes — scripts never become live DOM.',
    attack: '<script>alert()</script> or img onerror payload stored as note',
    defense: 'React JSX text-node rendering; stored content is never inserted as HTML',
    Component: XssPrevPanel,
  },
  {
    id: 'rate-limit',
    title: 'API Rate Limiting',
    owasp: 'OWASP A05:2021',
    color: 'cyan',
    Icon: Zap,
    concept: 'Automated scripts flood an API endpoint to scrape data or cause denial-of-service. Per-endpoint rate limits detect the burst and return HTTP 429 to block the client.',
    attack: 'Repeated rapid requests to a dedicated WAS lab endpoint',
    defense: 'slowapi @limiter.limit(10/minute) isolated from business API traffic → HTTP 429',
    Component: RateLimitPanel,
  },
];

function AccordionPanel({ panel, isOpen, onToggle }) {
  const c = C[panel.color];
  const { Icon, Component } = panel;
  return (
    <div className={`rounded-2xl border ${c.border} ${c.bg} overflow-hidden transition-all`}>
      {/* Header — always visible */}
      <button
        onClick={onToggle}
        className="w-full flex items-center justify-between p-5 text-left group"
      >
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-xl ${c.bg} border ${c.border}`}>
            <Icon className={`w-5 h-5 ${c.text}`} />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-100">{panel.title}</h3>
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full ${c.badge}`}>{panel.owasp}</span>
          </div>
        </div>
        {isOpen
          ? <ChevronDown className="w-4 h-4 text-slate-500 shrink-0" />
          : <ChevronRight className="w-4 h-4 text-slate-500 shrink-0" />}
      </button>

      {/* Expanded content */}
      {isOpen && (
        <div className="px-5 pb-5 space-y-4 border-t border-slate-800/60">
          {/* Concept + chips */}
          <div className="pt-4">
            <p className="text-xs text-slate-400 leading-relaxed mb-3">{panel.concept}</p>
            <div className="grid grid-cols-2 gap-2 text-[11px]">
              <div className="bg-slate-900/60 rounded-lg p-2.5 border border-slate-800">
                <p className="text-slate-500 font-semibold mb-1">ATTACK VECTOR</p>
                <p className="text-slate-300 font-mono break-all">{panel.attack}</p>
              </div>
              <div className="bg-slate-900/60 rounded-lg p-2.5 border border-slate-800">
                <p className="text-slate-500 font-semibold mb-1">SECURITY CONTROL</p>
                <p className="text-slate-300 font-mono break-all">{panel.defense}</p>
              </div>
            </div>
          </div>
          {/* Interactive form */}
          <div className="border-t border-slate-800/60 pt-4">
            <Component />
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export const WasLabPage = () => {
  const [openId, setOpenId] = useState('brute-force');

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
            <ShieldAlert className="w-7 h-7 text-cyan-400" />
            WAS Security Lab
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Interactive Web Application Security testing — enter real attack inputs, fire live HTTP requests, observe actual responses.
          </p>
        </div>
        <div className="px-3 py-1.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono shrink-0">
          ADMINISTRATOR ONLY
        </div>
      </div>

      {/* Info bar */}
      <div className="flex items-center gap-3 p-4 bg-amber-500/10 border border-amber-500/30 rounded-xl text-xs text-amber-300">
        <AlertTriangle className="w-4 h-4 shrink-0" />
        <span>
          All tests execute <strong>real HTTP requests</strong> against live backend endpoints using isolated test accounts.
          Every test generates a <strong>[WAS-DEMO] SOC alert</strong> — view results in the Alerts page and escalate to incidents.
        </span>
      </div>

      {/* Accordion panels */}
      <div className="space-y-3">
        {PANELS.map(panel => (
          <AccordionPanel
            key={panel.id}
            panel={panel}
            isOpen={openId === panel.id}
            onToggle={() => setOpenId(openId === panel.id ? null : panel.id)}
          />
        ))}
      </div>

      {/* OWASP legend */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 text-xs text-slate-500">
        <p className="font-semibold text-slate-400 mb-2">OWASP Top 10 Coverage</p>
        <div className="flex flex-wrap gap-2">
          {['A01 — Broken Access Control', 'A03 — Injection (SQLi + XSS)', 'A05 — Security Misconfiguration', 'A07 — Auth Failures'].map(item => (
            <span key={item} className="px-2 py-1 bg-slate-800 rounded-lg">{item}</span>
          ))}
        </div>
      </div>
    </div>
  );
};
