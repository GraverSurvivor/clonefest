import sqlite3 from "sqlite3";
import path from "path";
import fs from "fs";

const DATA_DIR = path.join(process.cwd(), "data");
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_PATH = path.join(DATA_DIR, "aegisshare.db");

// Singleton database connection (shared across requests in the same process)
let _db: sqlite3.Database | null = null;

function getDb(): sqlite3.Database {
  if (!_db) {
    _db = new sqlite3.Database(DB_PATH);
    _db.serialize(() => {
      _db!.run(`
        CREATE TABLE IF NOT EXISTS pastes (
          id TEXT PRIMARY KEY,
          payload TEXT NOT NULL,
          burn_on_read INTEGER DEFAULT 0,
          deletion_token TEXT NOT NULL,
          expires_at INTEGER,
          created_at INTEGER NOT NULL
        )
      `);
    });
  }
  return _db;
}

// ---------- Typed helpers ----------

export interface PasteRow {
  id: string;
  payload: string;
  burn_on_read: number;
  deletion_token: string;
  expires_at: number | null;
  created_at: number;
}

export function dbGet<T>(sql: string, params: unknown[]): Promise<T | undefined> {
  return new Promise((resolve, reject) => {
    getDb().get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row as T);
    });
  });
}

export function dbRun(sql: string, params: unknown[]): Promise<void> {
  return new Promise((resolve, reject) => {
    getDb().run(sql, params, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

// Purge all expired pastes — called lazily on every API request
export async function purgeExpired(): Promise<void> {
  const now = Date.now();
  await dbRun(
    "DELETE FROM pastes WHERE expires_at IS NOT NULL AND expires_at < ?",
    [now]
  );
}
