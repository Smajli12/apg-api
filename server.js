import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import morgan from 'morgan';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import jwt from 'jsonwebtoken';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const {
  PORT = 8080,
  JWT_SECRET = 'CHANGE_ME_LONG_RANDOM',
  ADMIN_KEY = 'CHANGE_ME_ADMIN',
  CLIENTS_JSON = '{"client-001":{"domains":["example.com","www.example.com"],"active":true}}',
  SLACK_WEBHOOK_URL
} = process.env;

const CLIENTS = JSON.parse(CLIENTS_JSON);

const app = express();
app.use(helmet());
app.use(cors({ origin: true }));
app.use(express.json({ limit: '500kb' }));
app.use(morgan('tiny'));
app.use(rateLimit({ windowMs: 60_000, max: 120 }));

const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const ndjsonPath = path.join(dataDir, 'events.ndjson');

const PayloadSchema = z.object({
  clientId: z.string(),
  pageViewId: z.string().optional(),
  site: z.string().url(),
  host: z.string(),
  timestamp: z.string(),
  tagVersion: z.string(),
  gptLoaded: z.boolean(),
  domSlots: z.array(z.string()),
  registeredSlots: z.array(z.string()),
  notRegisteredInGPT: z.array(z.string()),
  wrongNetworkSlots: z.array(z.object({
    id: z.string(),
    adUnitPath: z.string()
  })).optional().default([]),
  requestedSizes: z.record(z.array(z.tuple([z.number(), z.number()]))).optional().default({}),
  adSlotSizes: z.array(z.object({ id: z.string(), width: z.number(), height: z.number()})).optional().default([]),
  emptySlots: z.array(z.string()).optional().default([]),
  slotsInViewport: z.array(z.string()).optional().default([]),
  screenResolution: z.string().optional().default(''),
  userAgent: z.string().optional().default(''),
  language: z.string().optional().default(''),
  timezone: z.string().optional().default(''),
  consent: z.object({
    gdprApplies: z.boolean().nullable(),
    hasConsent: z.boolean().nullable(),
    source: z.string()
  }).optional().default({ gdprApplies:null, hasConsent:null, source:'none' }),
  adBlockLikely: z.boolean().nullable().optional(),
  gptEvents: z.array(z.object({
    name: z.string(),
    id: z.string().nullable(),
    adUnitPath: z.string(),
    networkId: z.string(),
    ts: z.string(),
    isEmpty: z.boolean().optional(),
    renderedSize: z.array(z.number()).nullable().optional(),
    creativeId: z.string().nullable().optional(),
    lineItemId: z.string().nullable().optional(),
    latencyMs: z.number().optional()
  })).optional().default([]),
  routeChanged: z.boolean().optional().default(false),
  newDomSlots: z.array(z.string()).optional().default([])
});

function verifyBearer(req){
  const h = req.headers.authorization || '';
  const m = h.match(/^Bearer (.+)$/i);
  return m ? m[1] : null;
}
function issueSiteToken(clientId, siteId){
  return jwt.sign({ clientId, siteId }, JWT_SECRET, { expiresIn: '365d' });
}
function decodeSiteToken(token){
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}
async function notifySlack(text){
  if (!SLACK_WEBHOOK_URL) return;
  try {
    await fetch(SLACK_WEBHOOK_URL, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ text }) });
  } catch {}
}

app.get('/health', (req,res)=> res.json({ ok:true, ts: Date.now() }));

app.post('/admin/issue-token', (req,res)=>{
  if ((req.headers['x-admin-key']||'') !== ADMIN_KEY) {
    return res.status(403).json({ error: 'forbidden' });
  }
  const { clientId, siteId } = req.body || {};
  if (!clientId || !siteId) return res.status(400).json({ error: 'clientId and siteId required' });
  if (!CLIENTS[clientId]) return res.status(400).json({ error: 'unknown clientId' });
  if (CLIENTS[clientId].active === false) return res.status(400).json({ error: 'client inactive' });
  return res.json({ token: issueSiteToken(clientId, siteId) });
});

app.post('/ingest', (req,res)=>{
  const token = verifyBearer(req);
  if (!token) return res.status(401).json({ error: 'missing bearer token' });
  const decoded = decodeSiteToken(token);
  if (!decoded) return res.status(401).json({ error: 'invalid token' });

  const { clientId, siteId } = decoded;
  const client = CLIENTS[clientId];
  if (!client || client.active === false) return res.status(403).json({ error: 'client disabled' });

  const parsed = PayloadSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'invalid payload', details: parsed.error.flatten() });
  }
  const payload = parsed.data;

  const allowed = client.domains || [];
  const okDomain = allowed.some(d => payload.host === d || payload.host.endsWith('.' + d));
  if (!okDomain) return res.status(403).json({ error: 'host not allowed for this client' });

  const row = JSON.stringify({ receivedAt: new Date().toISOString(), clientId, siteId, ...payload }) + '\n';
  try {
  fs.appendFileSync(ndjsonPath, row); // siguran upis
  console.log('APPENDED', ndjsonPath);
} catch (err) {
  console.error('NDJSON append error:', err);
}
  
  if (!payload.gptLoaded) notifySlack(`⚠️ GPT not loaded on ${payload.host} ${payload.site}`);
  if (payload.wrongNetworkSlots?.length) notifySlack(`❌ Wrong networkId on ${payload.host}: ${JSON.stringify(payload.wrongNetworkSlots).slice(0,400)}`);
  if (payload.notRegisteredInGPT?.length) notifySlack(`🔎 Not registered in GPT: ${payload.notRegisteredInGPT.join(', ').slice(0,400)}`);

  res.json({ ok: true });
});

// === helpers to read NDJSON ===
function readLastNFromNdjson(n = 100, clientIdFilter = null, hostFilter = null) {
  try {
    const txt = fs.readFileSync(ndjsonPath, 'utf8');
    const lines = txt.trim().split('\n');
    const out = [];
    for (let i = lines.length - 1; i >= 0 && out.length < n; i--) {
      const obj = JSON.parse(lines[i]);
      if (clientIdFilter && obj.clientId !== clientIdFilter) continue;
      if (hostFilter && obj.host !== hostFilter) continue;
      out.push(obj);
    }
    return out.reverse();
  } catch {
    return [];
  }
}

function toCsv(rows) {
  if (!rows.length) return '';
  const cols = [
    'receivedAt','clientId','site','host','timestamp','tagVersion',
    'gptLoaded','domSlots','registeredSlots','notRegisteredInGPT',
    'wrongNetworkSlots','emptySlots','slotsInViewport','adBlockLikely'
  ];
  const safe = (v) => {
    if (Array.isArray(v)) return JSON.stringify(v);
    if (typeof v === 'object' && v !== null) return JSON.stringify(v);
    return String(v ?? '');
  };
  const header = cols.join(',');
  const body = rows.map(r => cols.map(c => `"${safe(r[c]).replace(/"/g,'""')}"`).join(',')).join('\n');
  return header + '\n' + body;
}

function makeSummary(rows) {
  const sum = {
    total: rows.length,
    pages: new Set(),
    hosts: new Set(),
    gptNotLoaded: 0,
    wrongNetworkHits: 0,
    notRegisteredHits: 0,
    emptySlotsHits: 0
  };
  rows.forEach(r => {
    sum.pages.add(r.site);
    sum.hosts.add(r.host);
    if (!r.gptLoaded) sum.gptNotLoaded++;
    sum.wrongNetworkHits += (r.wrongNetworkSlots || []).length;
    sum.notRegisteredHits += (r.notRegisteredInGPT || []).length;
    sum.emptySlotsHits += (r.emptySlots || []).length;
  });
  return {
    totalEvents: sum.total,
    distinctPages: sum.pages.size,
    distinctHosts: sum.hosts.size,
    gptNotLoadedEvents: sum.gptNotLoaded,
    wrongNetworkSlotsCount: sum.wrongNetworkHits,
    notRegisteredInGPTCount: sum.notRegisteredHits,
    emptySlotsCount: sum.emptySlotsHits
  };
}

// === ADMIN JSON: recent events ===
app.get('/admin/recent', (req, res) => {
  if ((req.headers['x-admin-key']||'') !== ADMIN_KEY) return res.status(403).json({ error: 'forbidden' });
  const clientId = req.query.clientId || null;
  const host = req.query.host || null;
  const limit = Math.min(parseInt(req.query.limit||'100',10), 1000);
  const rows = readLastNFromNdjson(limit, clientId, host);
  res.json({ ok:true, count: rows.length, items: rows });
});

// === ADMIN CSV export ===
app.get('/admin/export.csv', (req, res) => {
  if ((req.headers['x-admin-key']||'') !== ADMIN_KEY) return res.status(403).send('forbidden');
  const clientId = req.query.clientId || null;
  const host = req.query.host || null;
  const limit = Math.min(parseInt(req.query.limit||'500',10), 5000);
  const rows = readLastNFromNdjson(limit, clientId, host);
  const csv = toCsv(rows);
  res.setHeader('Content-Type','text/csv');
  res.setHeader('Content-Disposition','attachment; filename="apg-export.csv"');
  res.send(csv);
});

// === ADMIN summary (JSON) ===
app.get('/admin/summary', (req, res) => {
  if ((req.headers['x-admin-key']||'') !== ADMIN_KEY) return res.status(403).json({ error: 'forbidden' });
  const clientId = req.query.clientId || null;
  const host = req.query.host || null;
  const limit = Math.min(parseInt(req.query.limit||'500',10), 10000);
  const rows = readLastNFromNdjson(limit, clientId, host);
  res.json({ ok:true, clientId, host, range: limit, summary: makeSummary(rows) });
});

// === PUBLIC report (HTML) – deliš klijentu link sa REPORT_KEY ===
app.get('/report', (req,res) => {
  const { key, clientId, host } = req.query;
  if (!key || key !== (process.env.REPORT_KEY||'')) return res.status(403).send('forbidden');
  const limit = Math.min(parseInt(req.query.limit||'200',10), 1000);
  const rows = readLastNFromNdjson(limit, clientId||null, host||null);
  const summary = makeSummary(rows);
  const escape = (s)=> String(s??'').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
  const tr = rows.map(r => `
    <tr>
      <td>${escape(r.timestamp)}</td>
      <td>${escape(r.site)}</td>
      <td>${escape(r.host)}</td>
      <td>${r.gptLoaded ? '✅' : '❌'}</td>
      <td>${(r.wrongNetworkSlots||[]).length}</td>
      <td>${(r.notRegisteredInGPT||[]).length}</td>
      <td>${(r.emptySlots||[]).length}</td>
    </tr>`).join('');
  res.setHeader('Content-Type','text/html; charset=utf-8');
  res.send(`<!doctype html>
<html><head><meta charset="utf-8"><title>APG Report</title>
<style>
body{font-family:system-ui,Arial,sans-serif;margin:24px}
h1{font-size:20px;margin:0 0 12px}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin:12px 0 20px}
.card{border:1px solid #ddd;border-radius:10px;padding:12px}
table{width:100%;border-collapse:collapse}
th,td{border:1px solid #eee;padding:6px 8px;font-size:12px;text-align:left}
th{background:#fafafa}
small{color:#666}
</style>
</head>
<body>
<h1>APG Report <small>clientId=${escape(clientId||'-')} host=${escape(host||'-')}</small></h1>
<div class="grid">
  <div class="card"><b>Total events</b><div>${summary.totalEvents}</div></div>
  <div class="card"><b>Distinct pages</b><div>${summary.distinctPages}</div></div>
  <div class="card"><b>GPT not loaded</b><div>${summary.gptNotLoadedEvents}</div></div>
  <div class="card"><b>Wrong network (slots)</b><div>${summary.wrongNetworkSlotsCount}</div></div>
  <div class="card"><b>Not registered in GPT (ids)</b><div>${summary.notRegisteredInGPTCount}</div></div>
  <div class="card"><b>Empty slots</b><div>${summary.emptySlotsCount}</div></div>
</div>
<table>
<thead><tr>
  <th>Timestamp</th><th>Page</th><th>Host</th><th>GPT</th>
  <th>Wrong net</th><th>Not in GPT</th><th>Empty</th>
</tr></thead>
<tbody>${tr || '<tr><td colspan="7">No data</td></tr>'}</tbody>
</table>
</body></html>`);
});

app.listen(PORT, () => {
  console.log(`APG API on :${PORT}`);
});



