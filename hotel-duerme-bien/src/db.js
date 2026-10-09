import { DatabaseSync } from 'node:sqlite';

export function openDb(file = ':memory:') {
  const db = new DatabaseSync(file);
  db.exec(`
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('admin','encargado')),
      created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
      csrf TEXT NOT NULL, expires_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS rooms (
      id INTEGER PRIMARY KEY, number INTEGER NOT NULL,
      capacity INTEGER NOT NULL CHECK (capacity BETWEEN 1 AND 10),
      orientation TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_room_number ON rooms(number) WHERE deleted = 0;
    CREATE TABLE IF NOT EXISTS assignments (
      id INTEGER PRIMARY KEY, total_cost INTEGER NOT NULL, created_at TEXT NOT NULL,
      checked_out_at TEXT, user_id INTEGER NOT NULL REFERENCES users(id));
    CREATE TABLE IF NOT EXISTS passengers (
      id INTEGER PRIMARY KEY, assignment_id INTEGER NOT NULL REFERENCES assignments(id),
      room_id INTEGER NOT NULL REFERENCES rooms(id), full_name TEXT NOT NULL,
      rut TEXT NOT NULL, is_responsible INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY, ts TEXT NOT NULL, username TEXT, action TEXT NOT NULL,
      detail TEXT, ip TEXT);
  `);
  return db;
}

export const audit = (db, username, action, detail = '', ip = '') =>
  db.prepare('INSERT INTO audit_log (ts,username,action,detail,ip) VALUES (?,?,?,?,?)')
    .run(new Date().toISOString(), username, action, String(detail).slice(0, 300), ip);
