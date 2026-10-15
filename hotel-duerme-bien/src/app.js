// Capa de presentación/API: HTTP, sesiones, control de acceso, cabeceras seguras
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { audit } from './db.js';
import * as S from './security.js';
import * as svc from './services.js';

const { HttpError } = S;
const PUBLIC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../public');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css' };
const SESSION_MS = 8 * 3600 * 1000;
const DUMMY_HASH = S.hashPassword('dummy-password-1'); // evita enumeración de usuarios por tiempo

export function createApp(db, { secure = false, trustProxy = false } = {}) {
  // Detrás de un proxy cloud la IP real viene en X-Forwarded-For (el último valor lo agrega el proxy)
  const clientIp = (req) => (trustProxy && req.headers['x-forwarded-for']
    ? String(req.headers['x-forwarded-for']).split(',').pop().trim() : req.socket.remoteAddress ?? '');
  const cookie = (v, age) => `sid=${v}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${age}${secure ? '; Secure' : ''}`;

  function getSession(req) {
    const m = /(?:^|;\s*)sid=([a-f0-9]{64})/.exec(req.headers.cookie ?? '');
    if (!m) return null;
    const s = db.prepare(`SELECT s.token_hash, s.csrf_token AS csrf, s.expires_at, u.id, u.username, u.role
      FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?`).get(S.sha256(m[1]));
    if (!s || s.expires_at < Date.now()) return null;
    return s;
  }

  async function readJson(req) {
    let size = 0; const chunks = [];
    for await (const c of req) { size += c.length; if (size > 10_000) throw new HttpError(413, 'Solicitud demasiado grande'); chunks.push(c); }
    if (!size) return {};
    try { return JSON.parse(Buffer.concat(chunks)); } catch { throw new HttpError(400, 'JSON inválido'); }
  }

  const id = (p) => { const n = Number(p); if (!Number.isInteger(n)) throw new HttpError(400, 'Id inválido'); return n; };

  // [método, ruta, roles permitidos (null = pública), handler]
  const routes = [
    ['POST', /^\/api\/login$/, null, (c) => {
      const { username, password } = c.body;
      if (typeof username !== 'string' || typeof password !== 'string' || username.length > 100 || password.length > 200) throw new HttpError(400, 'Datos inválidos');
      const keys = [`u:${username.toLowerCase()}`, `ip:${c.ip}`]; // bloqueo por usuario o por IP
      S.checkLock(keys);
      const u = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
      const ok = S.verifyPassword(password, u ? u.password_hash : DUMMY_HASH) && !!u;
      if (!ok) { S.registerFail(keys); audit(db, { id: u?.id ?? null, username: username.slice(0, 50) }, 'login', 'fallido', c.ip); throw new HttpError(401, 'Credenciales inválidas'); }
      S.clearFails(keys);
      const token = randomBytes(32).toString('hex'), csrf = randomBytes(16).toString('hex');
      db.prepare('INSERT INTO sessions (token_hash,user_id,csrf_token,expires_at) VALUES (?,?,?,?)').run(S.sha256(token), u.id, csrf, Date.now() + SESSION_MS);
      audit(db, u, 'login', 'exitoso', c.ip);
      c.res.setHeader('Set-Cookie', cookie(token, SESSION_MS / 1000));
      return { username: u.username, role: u.role, csrf };
    }],
    ['POST', /^\/api\/logout$/, ['admin', 'encargado'], (c) => {
      db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(c.session.token_hash);
      audit(db, c.session, 'logout', '', c.ip);
      c.res.setHeader('Set-Cookie', cookie('', 0));
      return { ok: true };
    }],
    ['GET', /^\/api\/me$/, ['admin', 'encargado'], (c) => ({ username: c.session.username, role: c.session.role, csrf: c.session.csrf })],
    ['GET', /^\/api\/health$/, null, () => ({ status: 'ok' })],
    // RF05: solo el Administrador registra Encargados (perfil único por usuario, RF03)
    ['POST', /^\/api\/users$/, ['admin'], (c) => {
      const { username, password } = c.body;
      if (!S.validUsername(username)) throw new HttpError(400, 'Usuario inválido (3-30 caracteres alfanuméricos . _ -)');
      if (!S.validPassword(password)) throw new HttpError(400, 'Contraseña: mínimo 10 caracteres con letras y números');
      if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(username)) throw new HttpError(409, 'El usuario ya existe');
      db.prepare('INSERT INTO users (username,password_hash,role,created_at) VALUES (?,?,?,?)')
        .run(username, S.hashPassword(password), 'encargado', new Date().toISOString());
      audit(db, c.session, 'create_user', username, c.ip);
      c.status = 201; return { username, role: 'encargado' };
    }],
    ['GET', /^\/api\/users$/, ['admin'], () => db.prepare('SELECT username, role, created_at FROM users ORDER BY id').all()],
    ['GET', /^\/api\/audit$/, ['admin'], (c) => svc.listAudit(db, Object.fromEntries(c.url.searchParams))],
    ['GET', /^\/api\/rooms$/, ['admin', 'encargado'], () => svc.listRooms(db)],
    ['POST', /^\/api\/rooms$/, ['encargado'], (c) => {
      const r = svc.createRoom(db, c.body); audit(db, c.session, 'create_room', `#${r.number}`, c.ip); c.status = 201; return r;
    }],
    ['DELETE', /^\/api\/rooms\/(\d+)$/, ['encargado'], (c) => {
      const r = svc.deleteRoom(db, id(c.m[1])); audit(db, c.session, 'delete_room', `#${r.number}`, c.ip); return { ok: true };
    }],
    ['POST', /^\/api\/assignments$/, ['encargado'], (c) => {
      const a = svc.assign(db, c.session.id, c.body); audit(db, c.session, 'assign_passengers', `asig ${a.id}`, c.ip); c.status = 201; return a;
    }],
    ['POST', /^\/api\/assignments\/(\d+)\/checkout$/, ['encargado'], (c) => {
      svc.checkout(db, id(c.m[1])); audit(db, c.session, 'checkout', c.m[1], c.ip); return { ok: true };
    }],
    ['GET', /^\/api\/passengers$/, ['admin', 'encargado'], () => svc.listGuests(db)],
  ];

  async function api(req, res, url) {
    const route = routes.map((r) => [r, r[1].exec(url.pathname)]).find(([r, m]) => m && r[0] === req.method);
    if (!route) throw new HttpError(404, 'No encontrado');
    const [[method, , roles, handler], m] = route;
    const session = getSession(req);
    if (roles) { // A01 Control de acceso roto: verificación en el servidor, por rol
      if (!session) throw new HttpError(401, 'No autenticado');
      if (!roles.includes(session.role)) throw new HttpError(403, 'Sin permisos para esta acción');
      if (method !== 'GET') { // protección CSRF (doble verificación: SameSite + token)
        const t = Buffer.from(String(req.headers['x-csrf-token'] ?? ''));
        const e = Buffer.from(session.csrf);
        if (t.length !== e.length || !timingSafeEqual(t, e)) throw new HttpError(403, 'Token CSRF inválido');
      }
    }
    const ctx = { req, res, url, m, session, ip: clientIp(req), status: 200, body: method === 'GET' || method === 'DELETE' ? {} : await readJson(req) };
    const out = handler(ctx);
    send(res, ctx.status, out);
  }

  const send = (res, status, data) => {
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify(data));
  };

  function serveStatic(res, pathname) {
    const file = path.resolve(PUBLIC, '.' + (pathname === '/' ? '/index.html' : pathname));
    if (!file.startsWith(PUBLIC + path.sep) || !MIME[path.extname(file)] || !fs.existsSync(file)) throw new HttpError(404, 'No encontrado');
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] });
    res.end(fs.readFileSync(file));
  }

  return http.createServer(async (req, res) => {
    // A05 Configuración insegura: cabeceras de seguridad
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    if (secure) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    try {
      const url = new URL(req.url, 'http://localhost');
      if (url.pathname.startsWith('/api/')) await api(req, res, url);
      else if (req.method === 'GET') serveStatic(res, url.pathname);
      else throw new HttpError(405, 'Método no permitido');
    } catch (e) {
      const status = e instanceof HttpError ? e.status : 500;
      if (status === 500) console.error(e); // A09: el detalle queda en logs, no en la respuesta
      send(res, status, { error: status === 500 ? 'Error interno del servidor' : e.message });
    }
  });
}
