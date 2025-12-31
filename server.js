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
  CLIENTS_JSON = '{"client-001":{"domains":["example.com"],"active":true}}',
  SHEET_WEBHOOK_URL
} = process.env;

const CLIENTS = JSON.parse(CLIENTS_JSON);

const app = express();

/* ======================================================
   🔧 RENDER FIX #1 — TRUST PROXY (OBAVEZNO)
   ====================================================== */
app.set("trust proxy", 1);

/* ======================================================
   🔧 RENDER FIX #2 — ROOT ROUTE
   ====================================================== */
app.get("/", (_req, res) =>
  res.status(200).send("APG API running. Try /health")
);

/* ================== MIDDLEWARE ================== */
app.use(helmet());
app.use(express.json({ limit: "500kb" }));
app.use(morgan("tiny"));
app.use(
  rateLimit({
    windowMs: 60_000,
    max: 240
  })
);

/* ================== CORS ================== */
function originAllowed(origin) {
  if (!origin) return false;
  try {
    const u = new URL(origin);
    const h = u.hostname;

    return Object.values(CLIENTS).some((c) => {
      if (!c || c.active === false) return false;
      return (c.domains || []).some(
        (d) => h === d || h.endsWith("." + d)
      );
    });
  } catch {
    return false;
  }
}

app.use(
  cors({
    origin(origin, cb) {
      if (!origin) return cb(null, true);
      if (originAllowed(origin)) return cb(null, true);
      return cb(new Error("CORS: origin not allowed"), false);
    },
    methods: ["POST", "GET", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "X-APG-Tag-Version",
      "X-Admin-Key"
    ],
    maxAge: 86400,
    credentials: false
  })
);

app.options("*", cors());
app.use((req, res, next) => {
  res.setHeader("Vary", "Origin");
  next();
});

/* ================== STORAGE ================== */
const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const ndjsonPath = path.join(dataDir, "events.ndjson");

/* ================== TOKEN HELPERS ================== */
function verifyBearer(req) {
  const h = req.headers.authorization || "";
  const m = h.match(/^Bearer (.+)$/i);
  return m ? m[1] : null;
}

function issueSiteToken(clientId) {
  return jwt.sign({ clientId }, JWT_SECRET, { expiresIn: "365d" });
}

function decodeSiteToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

/* ================== SCHEMA ================== */
const IssuePayloadSchema = z.object({
  clientId: z.string(),
  host: z.string(),
  pageUrl: z.string().url(),
  timestamp: z.string(),
  tagVersion: z.string().optional().default(""),
  userAgent: z.string().optional().default(""),

  issueType: z.enum([
    "gpt_not_loaded",
    "wrong_network",
    "slot_not_registered",
    "empty_response",
    "unexpected_size"
  ]),
  severity: z.string().optional().default("low"),

  slotId: z.string().optional().default(""),
  adUnitPath: z.string().optional().default(""),
  networkId: z.string().optional().default(""),
  renderedSize: z.string().optional(),
  definedSizes: z.array(z.string()).optional(),

  estimationCurrency: z.string().optional(),
  estimationWindowHours: z.number().optional(),
  assumedRpm: z.number().optional(),
  assumedImpressionsAtRisk: z.number().optional(),
  estimatedRevenueAtRisk: z.number().optional(),
  estimationMethod: z.string().optional()
});

/* ================== SHEET SENDER ================== */
async function postToSheet(row) {
  if (!SHEET_WEBHOOK_URL) return;
  try {
    await fetch(SHEET_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ row })
    });
  } catch (e) {
    console.error("Sheet post failed:", e?.message || e);
  }
}

/* ================== HEALTH ================== */
app.get("/health", (_req, res) =>
  res.json({ ok: true, ts: Date.now() })
);

/* ================== ADMIN ================== */
app.post("/admin/issue-token", (req, res) => {
  if ((req.headers["x-admin-key"] || "") !== ADMIN_KEY) {
    return res.status(403).json({ error: "forbidden" });
  }

  const { clientId } = req.body || {};
  if (!clientId) return res.status(400).json({ error: "clientId required" });

  const client = CLIENTS[clientId];
  if (!client || client.active === false) {
    return res.status(403).json({ error: "client disabled" });
  }

  return res.json({ token: issueSiteToken(clientId) });
});

/* ================== INGEST ================== */
app.post("/ingest", async (req, res) => {
  const token = verifyBearer(req);
  if (!token) return res.status(401).json({ error: "missing bearer token" });

  const decoded = decodeSiteToken(token);
  if (!decoded) return res.status(401).json({ error: "invalid token" });

  const { clientId } = decoded;
  const client = CLIENTS[clientId];
  if (!client || client.active === false) {
    return res.status(403).json({ error: "client disabled" });
  }

  const parsed = IssuePayloadSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "invalid payload" });
  }

  const payload = parsed.data;

  const allowed = client.domains || [];
  const okDomain = allowed.some(
    (d) => payload.host === d || payload.host.endsWith("." + d)
  );
  if (!okDomain) return res.status(403).json({ error: "host not allowed" });

  const event = {
    receivedAt: new Date().toISOString(),
    clientId,
    ...payload
  };

  fs.appendFileSync(ndjsonPath, JSON.stringify(event) + "\n");

  await postToSheet([
    event.receivedAt,
    event.clientId,
    event.host,
    event.pageUrl,
    event.issueType,
    event.severity,
    event.slotId || "",
    event.adUnitPath || "",
    event.networkId || "",
    event.tagVersion || "",
    event.estimationCurrency || "",
    event.estimationWindowHours ?? "",
    event.assumedRpm ?? "",
    event.assumedImpressionsAtRisk ?? "",
    event.estimatedRevenueAtRisk ?? "",
    event.estimationMethod || ""
  ]);

  return res.json({ ok: true });
});

/* ================== START ================== */
app.listen(PORT, () => {
  console.log(`APG API on :${PORT}`);
});
