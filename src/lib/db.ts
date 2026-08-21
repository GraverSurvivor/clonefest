import sqlite3 from "sqlite3";
import path from "path";
import fs from "fs";

const DATA_DIR = path.join(process.cwd(), "data");
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_PATH = path.join(DATA_DIR, "aegisshare.db");

let _db: sqlite3.Database | null = null;
let _ready: Promise<void> | null = null;

function migratePastes(db: sqlite3.Database): Promise<void> {
  // Recon note: the original schema was guest-only. These additive columns preserve old links.
  return new Promise((resolve, reject) => {
    db.all("PRAGMA table_info(pastes)", (err, rows: Array<{ name: string }> = []) => {
      if (err) {
        reject(err);
        return;
      }
      const columns = new Set(rows.map((row) => row.name));
      const additions: Array<[string, string]> = [
        ["mode", "TEXT NOT NULL DEFAULT 'guest'"],
        ["sender_id", "TEXT"],
        ["recipient_id", "TEXT"],
        ["wrapped_key", "TEXT"],
        ["key_metadata", "TEXT"],
        ["opened_at", "INTEGER"],
        ["revoked_at", "INTEGER"],
        ["deleted_at", "INTEGER"],
      ];
      const pending = additions.filter(([name]) => !columns.has(name));
      if (pending.length === 0) {
        resolve();
        return;
      }
      let remaining = pending.length;
      for (const [name, definition] of pending) {
        db.run(`ALTER TABLE pastes ADD COLUMN ${name} ${definition}`, (alterErr) => {
          if (alterErr) reject(alterErr);
          else if (--remaining === 0) resolve();
        });
      }
    });
  });
}

function initDb(): Promise<sqlite3.Database> {
  if (_db && _ready) return _ready.then(() => _db!);
  _db = new sqlite3.Database(DB_PATH);
  _ready = new Promise((resolve, reject) => {
    _db!.serialize(async () => {
      try {
        await new Promise<void>((res, rej) => _db!.run("PRAGMA foreign_keys = ON", (e) => (e ? rej(e) : res())));
        await new Promise<void>((res, rej) =>
          _db!.run(
            `CREATE TABLE IF NOT EXISTS pastes (
              id TEXT PRIMARY KEY,
              payload TEXT NOT NULL,
              burn_on_read INTEGER DEFAULT 0,
              deletion_token TEXT NOT NULL,
              expires_at INTEGER,
              created_at INTEGER NOT NULL
            )`,
            (e) => (e ? rej(e) : res())
          )
        );
        await new Promise<void>((res, rej) =>
          _db!.run(
            `CREATE TABLE IF NOT EXISTS users (
              id TEXT PRIMARY KEY,
              username TEXT NOT NULL UNIQUE COLLATE NOCASE,
              email TEXT NOT NULL UNIQUE COLLATE NOCASE,
              password_hash TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL
            )`,
            (e) => (e ? rej(e) : res())
          )
        );
        await new Promise<void>((res, rej) =>
          _db!.run(
            `CREATE TABLE IF NOT EXISTS user_keys (
              user_id TEXT PRIMARY KEY,
              public_key TEXT NOT NULL,
              encrypted_private_key TEXT NOT NULL,
              key_metadata TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )`,
            (e) => (e ? rej(e) : res())
          )
        );
        await new Promise<void>((res, rej) =>
          _db!.run(
            `CREATE TABLE IF NOT EXISTS sessions (
              id TEXT PRIMARY KEY,
              user_id TEXT NOT NULL,
              token_hash TEXT NOT NULL UNIQUE,
              expires_at INTEGER NOT NULL,
              created_at INTEGER NOT NULL,
              revoked_at INTEGER,
              FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )`,
            (e) => (e ? rej(e) : res())
          )
        );
        await migratePastes(_db!);
        await new Promise<void>((res, rej) =>
          _db!.run("CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash)", (e) => (e ? rej(e) : res()))
        );
        await new Promise<void>((res, rej) =>
          _db!.run("CREATE INDEX IF NOT EXISTS idx_pastes_recipient ON pastes(recipient_id, created_at)", (e) => (e ? rej(e) : res()))
        );
        await new Promise<void>((res, rej) =>
          _db!.run("CREATE INDEX IF NOT EXISTS idx_pastes_sender ON pastes(sender_id, created_at)", (e) => (e ? rej(e) : res()))
        );
        await new Promise<void>((res, rej) =>
          _db!.run("CREATE INDEX IF NOT EXISTS idx_pastes_expiry ON pastes(expires_at)", (e) => (e ? rej(e) : res()))
        );
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  });
  return _ready.then(() => _db!);
}

async function ensureDb(): Promise<sqlite3.Database> {
  return initDb();
}

export interface PasteRow {
  id: string;
  payload: string;
  burn_on_read: number;
  deletion_token: string;
  expires_at: number | null;
  created_at: number;
  mode: "guest" | "account";
  sender_id: string | null;
  recipient_id: string | null;
  wrapped_key: string | null;
  key_metadata: string | null;
  opened_at: number | null;
  revoked_at: number | null;
  deleted_at: number | null;
}

export interface UserRow {
  id: string;
  username: string;
  email: string;
  password_hash: string;
  created_at: number;
  updated_at: number;
}

export interface UserKeyRow {
  user_id: string;
  public_key: string;
  encrypted_private_key: string;
  key_metadata: string;
  created_at: number;
}

export interface SessionRow {
  id: string;
  user_id: string;
  token_hash: string;
  expires_at: number;
  created_at: number;
  revoked_at: number | null;
}

export function dbGet<T>(sql: string, params: unknown[] = []): Promise<T | undefined> {
  return ensureDb().then(
    (db) =>
      new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
          if (err) reject(err);
          else resolve(row as T);
        });
      })
  );
}

export function dbAll<T>(sql: string, params: unknown[] = []): Promise<T[]> {
  return ensureDb().then(
    (db) =>
      new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
          if (err) reject(err);
          else resolve(rows as T[]);
        });
      })
  );
}

export function dbRun(sql: string, params: unknown[] = []): Promise<void> {
  return ensureDb().then(
    (db) =>
      new Promise((resolve, reject) => {
        db.run(sql, params, (err) => {
          if (err) reject(err);
          else resolve();
        });
      })
  );
}

export function dbRunResult(sql: string, params: unknown[] = []): Promise<{ changes: number; lastID: number }> {
  return ensureDb().then(
    (db) =>
      new Promise((resolve, reject) => {
        db.run(sql, params, function runCallback(err) {
          if (err) reject(err);
          else resolve({ changes: this.changes, lastID: this.lastID });
        });
      })
  );
}

export async function purgeExpired(): Promise<void> {
  const now = Date.now();
  // Lazy cleanup fits this self-hosted app: every API request marks expired shares inaccessible.
  await dbRun(
    "UPDATE pastes SET deleted_at = ? WHERE expires_at IS NOT NULL AND expires_at < ? AND deleted_at IS NULL",
    [now, now]
  );
  await dbRun("DELETE FROM sessions WHERE expires_at < ? OR revoked_at IS NOT NULL", [now]);
}
