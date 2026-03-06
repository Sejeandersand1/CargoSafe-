const Database = require("better-sqlite3");

const db = new Database("cargosafe.db");
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','user')),
  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS quotes (
  id TEXT PRIMARY KEY,
  owner_id INTEGER NOT NULL,
  data_json TEXT NOT NULL,
  status TEXT NOT NULL,
  premium INTEGER,
  base_premium INTEGER,
  deductible_index INTEGER,
  rate REAL,
  area TEXT,
  lane TEXT,
  reasons_json TEXT,
  manual INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  offered_at INTEGER,
  accepted_at INTEGER,
  issued_at INTEGER,
  policy_number TEXT,
  FOREIGN KEY(owner_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS policies (
  id TEXT PRIMARY KEY,
  quote_id TEXT NOT NULL,
  owner_id INTEGER NOT NULL,
  policy_number TEXT UNIQUE NOT NULL,
  premium INTEGER NOT NULL,
  data_json TEXT NOT NULL,
  issued_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  FOREIGN KEY(owner_id) REFERENCES users(id),
  FOREIGN KEY(quote_id) REFERENCES quotes(id)
);
`);

// ✅ migration helpers (skal være UDENFOR db.exec stringen)
function addColumn(table, colDef) {
  try {
    db.prepare(`ALTER TABLE ${table} ADD COLUMN ${colDef}`).run();
  } catch (e) {
    if (!String(e.message).includes("duplicate column name")) throw e;
  }
}

addColumn("users", "company_name TEXT");
addColumn("users", "cvr TEXT");
addColumn("users", "company_address TEXT");
addColumn("users", "contact_name TEXT");
addColumn("users", "contact_phone TEXT");
addColumn("users", "contact_email TEXT");

module.exports = db;