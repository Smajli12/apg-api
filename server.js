import "dotenv/config";
import express from "express";
import helmet from "helmet";
import morgan from "morgan";
import cors from "cors";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import rateLimit from "express-rate-limit";
import { z } from "zod";
import jwt from "jsonwebtoken";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const {
  PORT = 8080,
  JWT_SECRET = "CHANGE_ME_LONG_RANDOM",
  ADMIN_KEY = "CHANGE_ME_ADMIN",
  CLIENTS_JSON = '{"client-001":{"domains":["example.com","www.example.com"],"active":true}}',
  REPORT_KEY = "CHANGE_ME_REPORT",
  SHEET_WEBHOOK_URL // Google Apps Script Web App URL (optional)
} = process.env;

const CLIENTS = JSON.parse(CLIENTS_JSON);

const app = express();
app.use(helmet());
app.use(express.json({ limit: "500kb" }));
app.use(morgan("tiny"));
app.use(rateLimit({ windowMs: 60_000, max: 240 }));

// ---------- CORS: allow only known client domains (browser Origin) ----------
function originAllowed(origin) {
  if (!origin) return false;
  try {
    const u = new URL(origin);
    const h = u.hostname;

    return Object.values(CLIENTS).some((c) => {
      if (!c || c.active === false) return false;
      const domains = c.domains || [];
      return domains.some((d) => h === d || h.endsWith("." + d));
    });
  } catch {
    return false;
  }
}

app.use(
  cors({
    origin: function (origin, cb) {
      // allow non-browser requests (no Origin header), e.g. curl/postman
      if (!origin) return cb(null, true);
      if (originAllowed(origin)) return cb(null, true);
      return cb(new Error("CORS: origin not allowed"), false);
    },
    methods: ["POST", "GET", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-APG-Tag-Version", "X-Admin-Key"],
    maxAge: 86400,
    credentials: false
  })
);

// ensure preflight works everywhere
app.options("*", cors());
app.use((req, res, next) => {
  res.setHeader("Vary", "Origin");
  next();
});

// ---------- Storage (NDJSON) ----------
const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const ndjsonPath = path.join(dataDir, "events.ndjson");

// ---------- Token helpers ----------
function verifyBearer(req) {
  const h = req.headers.authorization || "";
  const m = h.match(/^Bearer (.+)$/i);
  return m ? m[1] : null;
}
function issueSiteToken(clientId, siteId) {
  return jwt.sign({ clientId, siteId }, JWT_SECRET, { expiresIn: "365d" });
}
function decodeSiteToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

// ---------- Payload: issue-based (matches your current GTM tag) ----------
const IssuePayloadSchema = z.object({
  clientId: z.string(),
  host: z.string(),
  pageUrl: z.string().url(),
  timestamp: z.string(),
  tagVersion: z.string().optional().default(""),
  userAgent: z.string().optional().default(""),

  issueType: z.enum(["gpt_not_loaded", "wrong_network", "slot_not_registered", "empty_response", "unexpected_size"]),
  severity: z.string().optional().default("low"),

  slotId: z.string().optional().default(""),
  adUnitPath: z.string().optional().default(""),
  networkId: z.string().optional().default(""),
  renderedSize: z.string().optional(),
  definedSizes: z.array(z.string()).optional()
});

// ---------- Google Sheet sender (via Apps Script Web App) ----------
async function postToSheet(row) {
  if (!SHEET_WEBHOOK_URL) return;
  try {
    await fetch(SHEET_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      // send a single row; Apps Script will append
      body: JSON.stringify({ row })
    });
  } catch (e) {
    // never break ingest
    console.error("Sheet post failed:", e?.message || e);
  }
}

// ---------- Health ----------
app.get("/health", (_req, res) => res.json({ ok: true, ts: Date.now() }));

// ---------- Admin: issue token ----------
app.post("/admin/issue-token", (req, res) => {
  if ((req.headers["x-admin-key"] || "") !== ADMIN_KEY) {
    return res.status(403).json({ error: "forbidden" });
  }
  const { clientId, siteId } = req.body || {};
  if (!clientId || !siteId) return res.status(400).json({ error: "clientId and siteId required" });

  const client = CLIENTS[clientId];
  if (!client) return res.status(400).json({ error: "unknown clientId" });
  if (client.active === false) return res.status(400).json({ error: "client inactive" });

  return res.json({ token: issueSiteToken(clientId, siteId) });
});

// ---------- Ingest ----------
app.post("/ingest", async (req, res) => {
  const token = verifyBearer(req);
  if (!token) return res.status(401).json({ error: "missing bearer token" });

  const decoded = decodeSiteToken(token);
  if (!decoded) return res.status(401).json({ error: "invalid token" });

  const { clientId, siteId } = decoded;
  const client = CLIENTS[clientId];
  if (!client || client.active === false) return res.status(403).json({ error: "client disabled" });

  const parsed = IssuePayloadSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "invalid payload", details: parsed.error.flatten() });
  }

  const payload = parsed.data;

  // Host allow-list per client
  const allowed = client.domains || [];
  const okDomain = allowed.some((d) => payload.host === d || payload.host.endsWith("." + d));
  if (!okDomain) return res.status(403).json({ error: "host not allowed for this client" });

  const event = {
    receivedAt: new Date().toISOString(),
    clientId,
    siteId,
    ...payload
  };

  // NDJSON append
  try {
    fs.appendFileSync(ndjsonPath, JSON.stringify(event) + "\n");
  } catch (err) {
    console.error("NDJSON append error:", err);
  }

  // Send to Google Sheet (optional)
  // Choose the columns you want in Sheets:
  await postToSheet([
    event.receivedAt,
    event.clientId,
    event.siteId,
    event.host,
    event.pageUrl,
    event.issueType,
    event.severity,
    event.slotId || "",
    event.adUnitPath || "",
    event.networkId || "",
    event.tagVersion || ""
  ]);

  return res.json({ ok: true });
});

// ---------- Helpers: read NDJSON ----------
function readLastNFromNdjson(n = 100, clientIdFilter = null, hostFilter = null) {
  try {
    const txt = fs.readFileSync(ndjsonPath, "utf8");
    const lines = txt.trim().split("\n");
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

function makeSummary(rows) {
  const sum = {
    total: rows.length,
    hosts: new Set(),
    gptNotLoaded: 0,
    wrongNetwork: 0,
    notRegistered: 0,
    empty: 0,
    unexpectedSize: 0
  };
  rows.forEach((r) => {
    sum.hosts.add(r.host);
    if (r.issueType === "gpt_not_loaded") sum.gptNotLoaded++;
    if (r.issueType === "wrong_network") sum.wrongNetwork++;
    if (r.issueType === "slot_not_registered") sum.notRegistered++;
    if (r.issueType === "empty_response") sum.empty++;
    if (r.issueType === "unexpected_size") sum.unexpectedSize++;
  });
  return {
    totalEvents: sum.total,
    distinctHosts: sum.hosts.size,
    gptNotLoadedEvents: sum.gptNotLoaded,
    wrongNetworkEvents: sum.wrongNetwork,
    slotNotRegisteredEvents: sum.notRegistered,
    emptyResponseEvents: sum.empty,
    unexpectedSizeEvents: sum.unexpectedSize
  };
}

// ---------- Admin endpoints ----------
app.get("/admin/recent", (req, res) => {
  if ((req.headers["x-admin-key"] || "") !== ADMIN_KEY) return res.status(403).json({ error: "forbidden" });
  const clientId = req.query.clientId || null;
  const host = req.query.host || null;
  const limit = Math.min(parseInt(req.query.limit || "100", 10), 1000);
  const rows = readLastNFromNdjson(limit, clientId, host);
  res.json({ ok: true, count: rows.length, items: rows });
});

app.get("/admin/summary", (req, res) => {
  if ((req.headers["x-admin-key"] || "") !== ADMIN_KEY) return res.status(403).json({ error: "forbidden" });
  const clientId = req.query.clientId || null;
  const host = req.query.host || null;
  const limit = Math.min(parseInt(req.query.limit || "500", 10), 10000);
  const rows = readLastNFromNdjson(limit, clientId, host);
  res.json({ ok: true, clientId, host, range: limit, summary: makeSummary(rows) });
});

// ---------- Public report (HTML) ----------
app.get("/report", (req, res) => {
  const { key, clientId, host } = req.query;
  if (!key || key !== (REPORT_KEY || "")) return res.status(403).send("forbidden");

  const limit = Math.min(parseInt(req.query.limit || "200", 10), 1000);
  const rows = readLastNFromNdjson(limit, clientId || null, host || null);
  const summary = makeSummary(rows);

  const escape = (s) => String(s ?? "").replace(/[&<>"']/g, (m) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[m]));

  const tr = rows.map((r) => `
    <tr>
      <td>${escape(r.timestamp)}</td>
      <td>${escape(r.pageUrl)}</td>
      <td>${escape(r.host)}</td>
      <td>${escape(r.issueType)}</td>
      <td>${escape(r.slotId || "")}</td>
      <td>${escape(r.adUnitPath || "")}</td>
    </tr>`).join("");

  res.setHeader("Content-Type", "text/html; charset=utf-8");
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
  <div class="card"><b>Distinct hosts</b><div>${summary.distinctHosts}</div></div>
  <div class="card"><b>GPT not loaded</b><div>${summary.gptNotLoadedEvents}</div></div>
  <div class="card"><b>Wrong network</b><div>${summary.wrongNetworkEvents}</div></div>
  <div class="card"><b>Slot not registered</b><div>${summary.slotNotRegisteredEvents}</div></div>
  <div class="card"><b>Empty response</b><div>${summary.emptyResponseEvents}</div></div>
</div>

<table>
<thead><tr>
  <th>Timestamp</th><th>Page</th><th>Host</th><th>Issue</th><th>Slot</th><th>AdUnitPath</th>
</tr></thead>
<tbody>${tr || '<tr><td colspan="6">No data</td></tr>'}</tbody>
</table>
</body></html>`);
});

app.listen(PORT, () => {
  console.log(`APG API on :${PORT}`);
});
