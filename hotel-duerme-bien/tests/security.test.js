// Verificación de las afirmaciones OWASP del informe (CP-28 a CP-31)
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { openDb } from '../src/db.js';
import { createApp } from '../src/app.js';
import { hashPassword, resetAttempts } from '../src/security.js';

let db, servers = [];
const ADMIN = 'AdminPass123', ENC = 'Encargado123';
beforeEach(() => resetAttempts());
async function start(opts = {}) {
  const s = createApp(db, opts); await new Promise((r) => s.listen(0, r)); servers.push(s);
  return `http://localhost:${s.address().port}`;
}
before(() => {
  db = openDb(':memory:');
  const ins = db.prepare('INSERT INTO users (username,password_hash,role,created_at) VALUES (?,?,?,?)');
  ins.run('admin', hashPassword(ADMIN), 'admin', 'now'); ins.run('enc', hashPassword(ENC), 'encargado', 'now');
});
after(() => servers.forEach((s) => s.close()));
const api = (base) => async (method, url, body, s, raw) => {
  const r = await fetch(base + url, { method, headers: { 'Content-Type': 'application/json', ...(s ? { Cookie: s.cookie, 'X-CSRF-Token': s.csrf } : {}) }, body: raw ?? (body ? JSON.stringify(body) : undefined) });
  return { status: r.status, body: await r.json().catch(() => ({})), headers: r.headers };
};
const sess = async (call, u, p) => { const r = await call('POST', '/api/login', { username: u, password: p }); return { ...r, cookie: r.headers.get('set-cookie')?.split(';')[0], csrf: r.body.csrf }; };

test('CP-28 (A01) mínimo privilegio: el Administrador no accede a datos de la operación', async () => {
  const call = api(await start()), a = await sess(call, 'admin', ADMIN), e = await sess(call, 'enc', ENC);
  assert.equal((await call('GET', '/api/rooms', null, a)).status, 403);
  assert.equal((await call('GET', '/api/passengers', null, a)).status, 403);
  assert.equal((await call('GET', '/api/rooms', null, e)).status, 200);
  assert.equal((await call('GET', '/api/users', null, e)).status, 403);
});
test('CP-29 (A07) la sesión se invalida en el servidor al cerrar sesión y al vencer', async () => {
  const call = api(await start()), s = await sess(call, 'enc', ENC);
  assert.equal((await call('GET', '/api/me', null, s)).status, 200);
  assert.equal((await call('POST', '/api/logout', null, s)).status, 200);
  assert.equal((await call('GET', '/api/me', null, s)).status, 401); // el token viejo ya no sirve
  const s2 = await sess(call, 'enc', ENC);
  db.prepare('UPDATE sessions SET expires_at = 0').run(); // simula las 8 horas
  assert.equal((await call('GET', '/api/me', null, s2)).status, 401);
});
test('CP-30 (A03) entradas maliciosas: HTML/script, comodines SQL y cuerpos enormes', async () => {
  const call = api(await start()), a = await sess(call, 'admin', ADMIN), e = await sess(call, 'enc', ENC);
  const room = await call('POST', '/api/rooms', { number: 901, capacity: 1, orientation: 'vista al mar' }, e);
  const xss = await call('POST', '/api/assignments', { room_ids: [room.body.id], passengers: [{ name: '<img src=x onerror=alert(1)>', rut: '11111111-1', is_responsible: true }],
    start_date: new Date().toISOString().slice(0, 10), end_date: new Date(Date.now() + 86400000).toISOString().slice(0, 10) }, e);
  assert.equal(xss.status, 400); // el nombre con HTML no se guarda
  assert.equal((await call('POST', '/api/users', { username: '<script>alert(1)</script>', password: 'Clave12345678' }, a)).status, 400);
  for (const w of ['%25', '_']) assert.equal((await call('GET', `/api/audit?username=${w}`, null, a)).body.total, 0); // % y _ no son comodines
  assert.equal((await call('POST', '/api/login', null, null, JSON.stringify({ username: 'x'.repeat(20000), password: 'y' }))).status, 413);
});
test('CP-31 (A02, A05) cookie Secure y HSTS con HTTPS; por http plano la sesión sigue funcionando', async () => {
  const base = await start({ secure: true });
  const login = (h) => fetch(base + '/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json', ...h }, body: JSON.stringify({ username: 'enc', password: ENC }) });
  const https = await login({ 'X-Forwarded-Proto': 'https' }); // detrás de un proxy cloud con HTTPS
  const c1 = https.headers.get('set-cookie'); assert.match(c1, /Secure/); assert.match(c1, /HttpOnly/); assert.match(c1, /SameSite=Strict/);
  assert.match(https.headers.get('strict-transport-security'), /max-age=\d+/);
  const http = await login({}); // http plano: una cookie Secure sería descartada y el usuario volvería al ingreso en bucle
  const c2 = http.headers.get('set-cookie'); assert.doesNotMatch(c2, /Secure/); assert.match(c2, /HttpOnly/); assert.match(c2, /SameSite=Strict/);
  assert.equal(http.headers.get('strict-transport-security'), null);
});
