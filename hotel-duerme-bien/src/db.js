import { DatabaseSync } from 'node:sqlite';

const SCHEMA_VERSION = 4;
export const ORIENTATIONS = ['vista al mar', 'vista a la ciudad']; // columna rooms.orientation: tipo de vista
export const AUDIT_ACTIONS = ['login', 'logout', 'create_room', 'delete_room', 'assign_passengers', 'checkout', 'create_user', 'change_password', 'reset_password'];
const inList = (a) => a.map((x) => `'${x}'`).join(',');

export function openDb(file = ':memory:') {
  const db = new DatabaseSync(file);
  const exists = db.prepare("SELECT 1 FROM sqlite_master WHERE name='users'").get();
  const version = db.prepare('PRAGMA user_version').get().user_version;
  if (exists && version !== SCHEMA_VERSION)
    throw new Error('La base de datos tiene un esquema antiguo. Elimine el archivo data/hotel.db para recrearla (se perderán los datos de prueba).');
  db.exec(`
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      email TEXT UNIQUE COLLATE NOCASE,
      must_change_password INTEGER NOT NULL DEFAULT 0 CHECK (must_change_password IN (0,1)),
      role TEXT NOT NULL CHECK (role IN ('admin','encargado')),
      created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY, csrf_token TEXT NOT NULL,
      user_id INTEGER NOT NULL REFERENCES users(id), expires_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS login_challenges (
      token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
      code_salt TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0, resends INTEGER NOT NULL DEFAULT 0, last_sent_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS rooms (
      id INTEGER PRIMARY KEY, number INTEGER NOT NULL,
      capacity INTEGER NOT NULL CHECK (capacity BETWEEN 1 AND 10),
      orientation TEXT NOT NULL CHECK (orientation IN (${inList(ORIENTATIONS)})),
      deleted INTEGER NOT NULL DEFAULT 0 CHECK (deleted IN (0,1)), created_at TEXT NOT NULL);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_room_number ON rooms(number) WHERE deleted = 0;
    CREATE TABLE IF NOT EXISTS assignments (
      id INTEGER PRIMARY KEY, room_ids TEXT NOT NULL, total_cost INTEGER NOT NULL,
      start_date TEXT NOT NULL, end_date TEXT NOT NULL, nights INTEGER NOT NULL CHECK (nights BETWEEN 1 AND 365),
      created_at TEXT NOT NULL, user_id INTEGER NOT NULL REFERENCES users(id), checkout_at TEXT);
    CREATE TABLE IF NOT EXISTS passengers (
      id INTEGER PRIMARY KEY, assignment_id INTEGER NOT NULL REFERENCES assignments(id),
      name TEXT NOT NULL, rut TEXT NOT NULL, room_id INTEGER NOT NULL REFERENCES rooms(id),
      is_responsible INTEGER NOT NULL DEFAULT 0 CHECK (is_responsible IN (0,1)));
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), username TEXT,
      action TEXT NOT NULL CHECK (action IN (${inList(AUDIT_ACTIONS)})),
      details TEXT, ip_address TEXT, timestamp TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS ix_audit_action ON audit_log(action);
  `);
  db.exec(`PRAGMA user_version = ${SCHEMA_VERSION}`);
  return db;
}

// user = { id, username } (id puede ser null: sistema o intento con usuario inexistente)
export const audit = (db, user, action, details = '', ip = '') =>
  db.prepare('INSERT INTO audit_log (user_id,username,action,details,ip_address,timestamp) VALUES (?,?,?,?,?,?)')
    .run(user?.id ?? null, user?.username ?? null, action, String(details).slice(0, 300), String(ip).slice(0, 64), new Date().toISOString());
