require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("./db");

const app = express();

const ALLOWED = new Set([
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  "http://localhost:5500",
  "http://127.0.0.1:5500",
]);

const nodemailer = require("nodemailer");
const multer = require("multer");

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }
});

const host = (process.env.SMTP_HOST || "").trim();
const port = Number(process.env.SMTP_PORT || 587);

if(!host){
  console.error("SMTP_HOST mangler i .env");
}

const transporter = nodemailer.createTransport({
  host,
  port,
  secure: port === 465,
  requireTLS: port === 587,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  },
  tls: { servername: host }
});

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // file:// eller curl
    cb(null, ALLOWED.has(origin));
  },
  methods: ["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization"],
}));
app.options(/.*/, cors());

app.use(express.json());

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";

// ---------- basic routes ----------
app.get("/", (req, res) => {
  res.send("CargoSafe backend kører ✅");
});

app.get("/health", (req, res) => {
  res.json({ ok: true, service: "cargosafe-backend", time: new Date().toISOString() });
});

// ---------- helpers ----------
function now() { return Date.now(); }
function genId(prefix) {
  return `${prefix}-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
}
function signToken(user) {
  return jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: "8h" });
}
function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid/expired token" });
  }
}
function adminOnly(req, res, next) {
  if (req.user?.role !== "admin") return res.status(403).json({ error: "Admin only" });
  next();
}

// Admin: hent alle specielle forespørgsler (special_pending)
app.get("/api/admin/quotes/pending", auth, adminOnly, (req, res) => {
  const quotes = db.prepare(`
    SELECT q.id, q.owner_id, u.username AS owner,
           q.status, q.premium, q.created_at, q.reasons_json, q.data_json
    FROM quotes q
    LEFT JOIN users u ON u.id = q.owner_id
    WHERE q.status='special_pending'
    ORDER BY q.created_at DESC
  `).all();

  res.json({
    quotes: quotes.map(q => ({
      ...q,
      reasons: q.reasons_json ? JSON.parse(q.reasons_json) : [],
      data: q.data_json ? JSON.parse(q.data_json) : {}
    }))
  });
});

// Admin: hent alle policer
app.delete("/api/admin/quotes/:id", auth, adminOnly, (req, res) => {
  const id = String(req.params.id);

  const q = db.prepare("SELECT id, status FROM quotes WHERE id=?").get(id);
  if (!q) return res.status(404).json({ error: "Quote ikke fundet" });

  // Forhindr sletning hvis der findes police for quote
  const pol = db.prepare("SELECT id FROM policies WHERE quote_id=?").get(id);
  if (pol) return res.status(400).json({ error: "Slet policen først (policy findes)" });

  db.prepare("DELETE FROM quotes WHERE id=?").run(id);
  res.json({ ok: true });
});
  
// ---------- bootstrap admin ----------
(function bootstrapAdmin() {
  const u = process.env.ADMIN_BOOTSTRAP_USER || "admin";
  const p = process.env.ADMIN_BOOTSTRAP_PASS || "cargosafe123";

  const existing = db.prepare("SELECT * FROM users WHERE username=?").get(u);
  if (!existing) {
    const hash = bcrypt.hashSync(p, 12);
    db.prepare("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)")
      .run(u, hash, "admin", now());
    console.log("✅ Bootstrap admin oprettet:", u);
  } else {
    console.log("ℹ️ Admin findes allerede:", u);
  }
})();

// ---------- auth ----------
app.post("/api/auth/login", (req, res) => {
  const {
  username,
  password,
  role,
  companyName,
  cvr,
  companyAddress,
  contactName,
  contactPhone,
  contactEmail} = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "username/password required" });

  const user = db.prepare("SELECT * FROM users WHERE username=?").get(username);
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const ok = bcrypt.compareSync(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  const token = signToken(user);
  res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
});

app.get("/api/me", auth, (req, res) => {
  const u = db.prepare(`
    SELECT
      id, username, role,
      company_name AS companyName,
      cvr,
      company_address AS companyAddress,
      contact_name AS contactName,
      contact_phone AS contactPhone,
      contact_email AS contactEmail,
      created_at AS createdAt
    FROM users
    WHERE id = ?
  `).get(req.user.id);

  if (!u) return res.status(404).json({ error: "Bruger ikke fundet" });
  res.json({ user: u });
});
app.put("/api/me", auth, (req, res) => {
  const {
    companyName,
    cvr,
    companyAddress,
    contactName,
    contactPhone,
    contactEmail
  } = req.body || {};

  const clean = (s, max = 200) =>
    (typeof s === "string" ? s.trim().slice(0, max) : null);

  const info = db.prepare(`
    UPDATE users SET
      company_name = ?,
      cvr = ?,
      company_address = ?,
      contact_name = ?,
      contact_phone = ?,
      contact_email = ?
    WHERE id = ?
  `).run(
    clean(companyName, 120),
    clean(cvr, 20),
    clean(companyAddress, 200),
    clean(contactName, 120),
    clean(contactPhone, 40),
    clean(contactEmail, 120),
    req.user.id
  );

  if (info.changes === 0) return res.status(404).json({ error: "Bruger ikke fundet" });
  res.json({ ok: true });
});


// Admin opretter brugere (bevarer gamle)
app.post("/api/admin/users", auth, adminOnly, (req, res) => {
  const {
  username,
  password,
role,
  companyName,
  cvr,
  companyAddress,
  contactName,
  contactPhone,
  contactEmail
} = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "username/password required" });
  const r = (role === "admin") ? "admin" : "user";
  const exists = db.prepare("SELECT id FROM users WHERE username=?").get(username);
  if (exists) return res.status(409).json({ error: "Username already exists" });

  const hash = bcrypt.hashSync(password, 12);
  const createdAt = now();

const info = db.prepare(`
  INSERT INTO users (
    username, password_hash, role,
    company_name, cvr, company_address,
    contact_name, contact_phone, contact_email,
    created_at
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`).run(
  username,
  hash,
  r,
  companyName || null,
  cvr || null,
  companyAddress || null,
  contactName || null,
  contactPhone || null,
  contactEmail || null,
  createdAt
);

  res.json({ id: info.lastInsertRowid, username, role: r });
});

// Admin oversigt over brugere  ✅ (DENNE SKAL STÅ UDENFOR POST)
app.get("/api/admin/users", auth, adminOnly, (req, res) => {
  const users = db.prepare(`
  SELECT
    id, username, role,
    company_name AS companyName,
    cvr,
    company_address AS companyAddress,
    contact_name AS contactName,
    contact_phone AS contactPhone,
    contact_email AS contactEmail,
    created_at AS createdAt
  FROM users
  ORDER BY id DESC
`).all();

res.json({ users });

});

// ✅ Admin: opdater virksomheds-/kontaktinfo på en bruger
app.put("/api/admin/users/:id", auth, adminOnly, (req, res) => {
  const uid = Number(req.params.id);

  const {
    companyName,
    cvr,
    companyAddress,
    contactName,
    contactPhone,
    contactEmail
  } = req.body || {};

  const clean = (s, max=200) => (typeof s === "string" ? s.trim().slice(0, max) : null);

  const info = db.prepare(`
    UPDATE users SET
      company_name = ?,
      cvr = ?,
      company_address = ?,
      contact_name = ?,
      contact_phone = ?,
      contact_email = ?
    WHERE id = ?
  `).run(
    clean(companyName, 120),
    clean(cvr, 20),
    clean(companyAddress, 200),
    clean(contactName, 120),
    clean(contactPhone, 40),
    clean(contactEmail, 120),
    uid
  );

  if (info.changes === 0) return res.status(404).json({ error: "Bruger ikke fundet" });
  res.json({ ok: true });
});

// ✅ Admin: policer pr bruger (INDSÆT DENNE)
app.get("/api/admin/users/:id/policies", auth, adminOnly, (req, res) => {
  const uid = Number(req.params.id);

  const policies = db.prepare(`
    SELECT id, policy_number, premium, issued_at, data_json
    FROM policies
    WHERE owner_id=?
    ORDER BY issued_at DESC
  `).all(uid);

  res.json({
    policies: policies.map(p => ({
      ...p,
      data: p.data_json ? JSON.parse(p.data_json) : {}
    }))
  });
});

// ✅ Admin: hent alle policer (med owner info)
app.get("/api/admin/policies", auth, adminOnly, (req, res) => {
  const rows = db.prepare(`
    SELECT p.id, p.quote_id, p.owner_id, u.username AS owner,
           p.policy_number, p.premium, p.issued_at, p.data_json
    FROM policies p
    LEFT JOIN users u ON u.id = p.owner_id
    ORDER BY p.issued_at DESC
  `).all();

  res.json({
    policies: rows.map(p => ({
      ...p,
      data: p.data_json ? JSON.parse(p.data_json) : {}
    }))
  });
});

// ✅ Admin: slet udstedt police
app.delete("/api/admin/policies/:id", auth, adminOnly, (req, res) => {
  const pid = String(req.params.id);

  const policy = db.prepare("SELECT id, quote_id FROM policies WHERE id=?").get(pid);
  if (!policy) return res.status(404).json({ error: "Police ikke fundet" });

  // (valgfrit men smart) når policen slettes, ruller vi quote tilbage til "accepted"
  db.prepare("BEGIN").run();
  try {
    db.prepare("DELETE FROM policies WHERE id=?").run(pid);

    db.prepare(`
      UPDATE quotes
      SET status='accepted',
          issued_at=NULL,
          policy_number=NULL
      WHERE id=?
    `).run(policy.quote_id);

    db.prepare("COMMIT").run();
    res.json({ ok: true });
  } catch (e) {
    db.prepare("ROLLBACK").run();
    res.status(500).json({ error: e.message });
  }
});

// Admin: nulstil password
app.post("/api/admin/users/:id/reset-password", auth, adminOnly, (req, res) => {
  const uid = Number(req.params.id);
  const { password } = req.body || {};

  if (!password || String(password).length < 6) {
    return res.status(400).json({ error: "Password skal være mindst 6 tegn" });
  }

  const hash = bcrypt.hashSync(password, 12);
  const info = db.prepare("UPDATE users SET password_hash=? WHERE id=?").run(hash, uid);

  if (info.changes === 0) return res.status(404).json({ error: "Bruger ikke fundet" });
  res.json({ ok: true });
});

// Admin: slet bruger
app.delete("/api/admin/users/:id", auth, adminOnly, (req, res) => {
  const uid = Number(req.params.id);

  // Forhindr at admin sletter sig selv
  if(uid === req.user.id){
    return res.status(400).json({ error: "Du kan ikke slette din egen admin-bruger" });
  }

  const exists = db.prepare("SELECT id FROM users WHERE id=?").get(uid);
  if(!exists) return res.status(404).json({ error: "Bruger ikke fundet" });

  db.prepare("DELETE FROM policies WHERE owner_id=?").run(uid);
  db.prepare("DELETE FROM quotes WHERE owner_id=?").run(uid);
  db.prepare("DELETE FROM users WHERE id=?").run(uid);

  res.json({ ok: true });
});

// Admin: sæt manuel præmie og send tilbud
app.post("/api/admin/quotes/:id/set-premium", auth, adminOnly, (req, res) => {
  const id = String(req.params.id);
  const premium = Number(req.body?.premium || 0);

  if(!premium || premium <= 0){
    return res.status(400).json({ error: "Angiv en gyldig præmie" });
  }

  const info = db.prepare(`
    UPDATE quotes
    SET premium=?, status='offered', manual=1, offered_at=?
    WHERE id=?
  `).run(premium, Date.now(), id);

  if(info.changes === 0) return res.status(404).json({ error: "Quote ikke fundet" });
  res.json({ ok: true });
});
// ---------- quotes/policies flow ----------

// Bruger: opret quote (frontend sender beregnet / eller special_pending)
app.post("/api/quotes", auth, (req, res) => {
  const q = req.body || {};
  if (!q.data_json && !q.data) return res.status(400).json({ error: "Missing data" });

  const id = q.id || genId("QUOTE");
  const dataJson = q.data_json ? q.data_json : JSON.stringify(q.data);
  const status = q.status || "special_pending";

  db.prepare(`
    INSERT INTO quotes(id, owner_id, data_json, status, premium, base_premium, deductible_index, rate, area, lane,
      reasons_json, manual, created_at, offered_at, accepted_at, issued_at, policy_number)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  `).run(
    id,
    req.user.id,
    dataJson,
    status,
    q.premium ?? null,
    q.base_premium ?? null,
    q.deductible_index ?? null,
    q.rate ?? null,
    q.area ?? null,
    q.lane ?? null,
    q.reasons_json ? q.reasons_json : (q.reasons ? JSON.stringify(q.reasons) : null),
    q.manual ? 1 : 0,
    now(),
    q.offered_at ?? null,
    q.accepted_at ?? null,
    q.issued_at ?? null,
    q.policy_number ?? null
  );

  res.json({ id });
});

// Bruger: se egne quotes
app.get("/api/quotes", auth, (req, res) => {
  const quotes = db.prepare(`
    SELECT id, status, premium, base_premium, deductible_index, rate, area, lane,
           reasons_json, manual, created_at, offered_at, accepted_at, issued_at, policy_number, data_json
    FROM quotes
    WHERE owner_id=?
    ORDER BY created_at DESC
  `).all(req.user.id);

  const parsed = quotes.map(q => ({
    ...q,
    reasons: q.reasons_json ? JSON.parse(q.reasons_json) : [],
    data: q.data_json ? JSON.parse(q.data_json) : {}
  }));

  res.json({ quotes: parsed });
});

// Bruger: accepter quote OG udsted police i samme klik
app.post("/api/quotes/:id/accept", auth, (req, res) => {
  const id = String(req.params.id);

  // find quote (ejer)
  const q = db.prepare("SELECT * FROM quotes WHERE id=? AND owner_id=?").get(id, req.user.id);
  if (!q) return res.status(404).json({ error: "Quote not found" });

  // Hvis allerede udstedt: returnér eksisterende (idempotent)
  const existingPolicy = db.prepare("SELECT id, policy_number FROM policies WHERE quote_id=?").get(id);
  if (existingPolicy) {
    return res.json({ ok: true, issued: true, policyId: existingPolicy.id, policyNumber: existingPolicy.policy_number });
  }

  // Kun "offered" må accepteres
  if (q.status !== "offered") {
    return res.status(400).json({ error: "Quote not in offered state" });
  }

  const policyNumber =
    q.policy_number ||
    `CS-${new Date().toISOString().slice(0,10).replaceAll("-","")}-${String(Math.floor(Math.random()*10000)).padStart(4,"0")}`;

  const issuedAt = now();
  const acceptedAt = issuedAt;
  const policyId = genId("POL");

  db.prepare("BEGIN").run();
  try {
    // 1) accepter + markér som issued i samme flow
    db.prepare(`
      UPDATE quotes
      SET status='issued',
          accepted_at=?,
          issued_at=?,
          policy_number=?
      WHERE id=?
    `).run(acceptedAt, issuedAt, policyNumber, id);

    // 2) opret policy (brug q.data_json + q.premium)
    db.prepare(`
      INSERT INTO policies(id, quote_id, owner_id, policy_number, premium, data_json, issued_at)
      VALUES(?,?,?,?,?,?,?)
    `).run(policyId, id, req.user.id, policyNumber, q.premium, q.data_json, issuedAt);

    db.prepare("COMMIT").run();
    res.json({ ok: true, issued: true, policyNumber, policyId });
  } catch (e) {
    db.prepare("ROLLBACK").run();
    res.status(500).json({ error: e.message });
  }
});

// Bruger: udsted police (fra accepted)
app.post("/api/quotes/:id/issue", auth, (req, res) => {
  const id = req.params.id;
  const q = db.prepare("SELECT * FROM quotes WHERE id=? AND owner_id=?").get(id, req.user.id);
  if (!q) return res.status(404).json({ error: "Quote not found" });
  if (q.status !== "accepted") return res.status(400).json({ error: "Quote not accepted" });

  const policyNumber =
    q.policy_number ||
    `CS-${new Date().toISOString().slice(0,10).replaceAll("-","")}-${String(Math.floor(Math.random()*10000)).padStart(4,"0")}`;

  const issuedAt = now();
  const policyId = genId("POL");

  db.prepare("UPDATE quotes SET status='issued', issued_at=?, policy_number=? WHERE id=?")
    .run(issuedAt, policyNumber, id);

  db.prepare(`
    INSERT INTO policies(id, quote_id, owner_id, policy_number, premium, data_json, issued_at)
    VALUES(?,?,?,?,?,?,?)
  `).run(policyId, id, req.user.id, policyNumber, q.premium, q.data_json, issuedAt);

  res.json({ policyNumber, policyId });
});

// Bruger: se egne policer
app.get("/api/policies", auth, (req, res) => {
  const policies = db.prepare(`
    SELECT id, policy_number, premium, issued_at, data_json
    FROM policies
    WHERE owner_id=?
    ORDER BY issued_at DESC
  `).all(req.user.id);

  res.json({
    policies: policies.map(p => ({ ...p, data: JSON.parse(p.data_json) }))
  });
});
app.post("/api/claims", auth, upload.array("attachments", 5), async (req, res) => {
  try{
    const { policyholder, name, cvr, policyNo, email, phone, date, description } = req.body;

    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: false,
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    });

    const attachments = (req.files || []).map(f => ({
      filename: f.originalname,
      content: f.buffer,
      contentType: f.mimetype
    }));

    await transporter.sendMail({
      from: process.env.MAIL_FROM || process.env.SMTP_USER,
      to: "mail@curatio-insurance.com",
      replyTo: email,
      subject: `CargoSafe – Skadeanmeldelse (${policyNo})`,
      text:
`Forsikringstager: ${policyholder}
Navn: ${name}
CVR/CPR: ${cvr}
Police/Aftalenr.: ${policyNo}
Email: ${email}
Telefon: ${phone}
Dato: ${date}

Beskrivelse:
${description}
`,
      attachments
    });

    res.json({ ok: true });
  } catch(e){
    console.error(e);
    res.status(500).json({ error: "Kunne ikke sende skadeanmeldelsen." });
  }
});
app.listen(PORT, () => {
  console.log(`✅ Server kører på http://localhost:${PORT}`);
});
