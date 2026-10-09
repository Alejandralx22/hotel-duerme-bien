// Pruebas automatizadas: ejecutar con `npm test`. Cada test lleva el ID del caso de prueba (CP-xx).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { openDb } from '../src/db.js';
import { createApp } from '../src/app.js';
import { hashPassword } from '../src/security.js';

let server, base, db;
const ADMIN = 'AdminPass123', ENC = 'Encargado123';

before(async () => {
  db = openDb(':memory:');
  const ins = db.prepare('INSERT INTO users (username,password_hash,role,created_at) VALUES (?,?,?,?)');
  ins.run('admin', hashPassword(ADMIN), 'admin', 'now');
  ins.run('enc', hashPassword(ENC), 'encargado', 'now');
  server = createApp(db); await new Promise((r) => server.listen(0, r));
  base = `http://localhost:${server.address().port}`;
});
after(() => server.close());

async function call(method, url, body, s) {
  const r = await fetch(base + url, { method, headers: { 'Content-Type': 'application/json', ...(s ? { Cookie: s.cookie, 'X-CSRF-Token': s.csrf } : {}) }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, body: await r.json(), headers: r.headers };
}
async function login(username, password) {
  const r = await call('POST', '/api/login', { username, password });
  return { ...r, cookie: r.headers.get('set-cookie')?.split(';')[0], csrf: r.body.csrf };
}
const room = (s, number, capacity) => call('POST', '/api/rooms', { number, capacity, orientation: 'norte' }, s);
const P = (n, rut) => ({ full_name: n, rut });
function R(body) { // RUT válido (módulo 11)
  let sum = 0, mul = 2;
  for (let i = body.length - 1; i >= 0; i--) { sum += +body[i] * mul; mul = mul === 7 ? 2 : mul + 1; }
  const r = 11 - (sum % 11); return `${body}-${r === 11 ? '0' : r === 10 ? 'K' : r}`;
}

test('CP-01 login válido entrega sesión con cookie HttpOnly+SameSite', async () => {
  const r = await login('enc', ENC);
  assert.equal(r.status, 200);
  assert.match(r.headers.get('set-cookie'), /HttpOnly/); assert.match(r.headers.get('set-cookie'), /SameSite=Strict/);
});
test('CP-02 login con clave incorrecta -> 401 con mensaje genérico', async () => {
  const r = await login('enc', 'mala'); assert.equal(r.status, 401);
  assert.equal((await login('noexiste', 'mala')).body.error, r.body.error); // no revela si el usuario existe
});
test('CP-03 inyección SQL en login es rechazada', async () => {
  const r = await login("' OR '1'='1' --", "' OR '1'='1"); assert.equal(r.status, 401);
});
test('CP-04 bloqueo tras 5 intentos fallidos -> 429', async () => {
  for (let i = 0; i < 5; i++) await login('victima', 'x');
  assert.equal((await login('victima', 'x')).status, 429);
});
test('CP-05 contraseñas almacenadas con hash (RNF01)', () => {
  for (const u of db.prepare('SELECT password_hash FROM users').all()) { assert.match(u.password_hash, /^scrypt\$/); assert.ok(![ADMIN, ENC].some((p) => u.password_hash.includes(p))); }
});
test('CP-06 sin sesión -> 401; rol incorrecto -> 403 (control de acceso)', async () => {
  assert.equal((await call('GET', '/api/rooms')).status, 401);
  const enc = await login('enc', ENC);
  assert.equal((await call('POST', '/api/users', { username: 'x1234', password: 'Password123' }, enc)).status, 403);
});
test('CP-07 petición mutante sin token CSRF -> 403', async () => {
  const enc = await login('enc', ENC);
  const r = await fetch(base + '/api/rooms', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: enc.cookie }, body: JSON.stringify({ number: 1, capacity: 2, orientation: 'sur' }) });
  assert.equal(r.status, 403);
});
test('CP-08 (RF05) admin crea encargado y no puede tener ambos perfiles (RF03)', async () => {
  const a = await login('admin', ADMIN);
  const r = await call('POST', '/api/users', { username: 'nuevo.enc', password: 'ClaveSegura12' }, a);
  assert.equal(r.status, 201); assert.equal(r.body.role, 'encargado');
  assert.equal((await call('POST', '/api/users', { username: 'debil', password: '123' }, a)).status, 400);
});
test('CP-09 (RF06) número de habitación único', async () => {
  const s = await login('enc', ENC);
  assert.equal((await room(s, 101, 2)).status, 201); assert.equal((await room(s, 101, 3)).status, 409);
});
test('CP-10 (RF10) capacidad exacta: 1 o 3 pasajeros rechazados, 2 aceptados', async () => {
  const s = await login('enc', ENC); const r = await room(s, 102, 2); const ids = [r.body.id];
  const go = (ps) => call('POST', '/api/assignments', { room_ids: ids, passengers: ps, responsible_index: 0 }, s);
  assert.equal((await go([P('Ana Pérez', R('11111111'))])).status, 422);
  assert.equal((await go([P('Ana Pérez', R('11111111')), P('Luis Soto', R('22222222')), P('Eva Rojas', R('12345678'))])).status, 422);
  assert.equal((await go([P('Ana Pérez', R('11111111')), P('Luis Soto', R('22222222'))])).status, 201);
});
test('CP-11 (RF11) 3 pasajeros -> costo $120.000 y RF12 fecha registrada', async () => {
  const s = await login('enc', ENC); const r = await room(s, 103, 3);
  const a = await call('POST', '/api/assignments', { room_ids: [r.body.id], responsible_index: 1,
    passengers: [P('Pedro Díaz', R('7654321')), P('María Luna', R('9876543')), P('Juan Mora', R('15000000'))] }, s);
  assert.equal(a.body.total_cost, 120000);
  const g = (await call('GET', '/api/passengers', null, s)).body.filter((x) => x.room === 103);
  assert.equal(g.length, 3); assert.ok(g[0].created_at); assert.equal(g.filter((x) => x.responsible).length, 1);
});
test('CP-12 RUT inválido o repetido -> 400', async () => {
  const s = await login('enc', ENC); const r = await room(s, 104, 2);
  const go = (ps) => call('POST', '/api/assignments', { room_ids: [r.body.id], passengers: ps, responsible_index: 0 }, s);
  assert.equal((await go([P('Ana Pérez', '11111111-9'), P('Luis Soto', R('22222222'))])).status, 400);
  assert.equal((await go([P('Ana Pérez', R('22222222')), P('Luis Soto', R('22222222').replace(/^(\d{2})(\d{3})(\d{3})/, '$1.$2.$3'))])).status, 400);
});
test('CP-13 (RF07) no se elimina habitación con pasajeros activos; (RF08) tras check-out sí, conservando historial', async () => {
  const s = await login('enc', ENC); const r = await room(s, 105, 1);
  const a = await call('POST', '/api/assignments', { room_ids: [r.body.id], passengers: [P('Rosa Vega', R('16000000'))], responsible_index: 0 }, s);
  assert.equal((await call('DELETE', '/api/rooms/' + r.body.id, null, s)).status, 409);
  assert.equal((await call('POST', `/api/assignments/${a.body.id}/checkout`, null, s)).status, 200);
  assert.equal((await call('DELETE', '/api/rooms/' + r.body.id, null, s)).status, 200);
  assert.equal(db.prepare('SELECT COUNT(*) c FROM passengers WHERE room_id=?').get(r.body.id).c, 1);
});
test('CP-14 (RF13) varias habitaciones solo si el grupo excede la mayor disponible', async () => {
  const s = await login('enc', ENC);
  const a = (await room(s, 201, 2)).body.id, b = (await room(s, 202, 2)).body.id;
  const c = (await room(s, 301, 1)).body.id, d = (await room(s, 302, 1)).body.id;
  const go = (ids, ps) => call('POST', '/api/assignments', { room_ids: ids, passengers: ps, responsible_index: 0 }, s);
  // 2 pasajeros repartidos en 2 habitaciones de 1 -> rechazado: cabrían en una habitación de 2
  assert.equal((await go([c, d], [P('A Uno', R('10000013')), P('B Dos', R('10000014'))])).status, 422);
  // 4 pasajeros exceden la mayor habitación libre (2) -> aceptado en 2 habitaciones
  const ps = [P('A Uno', R('10000013')), P('B Dos', R('10000014')), P('C Tres', R('10000015')), P('D Cuatro', R('10000016'))];
  const ok = await go([a, b], ps); assert.equal(ok.status, 201); assert.equal(ok.body.total_cost, 160000);
});
test('CP-15 (RF15) estado ocupada/vacante en el resumen', async () => {
  const s = await login('enc', ENC); const rooms = (await call('GET', '/api/rooms', null, s)).body;
  assert.ok(rooms.some((r) => r.status === 'ocupada')); assert.ok(rooms.some((r) => r.status === 'vacante'));
});
test('CP-16 cabeceras de seguridad y sin fuga de errores internos', async () => {
  const r = await fetch(base + '/'); assert.match(r.headers.get('content-security-policy'), /default-src 'self'/);
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  const bad = await fetch(base + '/api/login', { method: 'POST', body: '{malformado' }); assert.equal(bad.status, 400);
});
test('CP-17 path traversal en archivos estáticos bloqueado', async () => {
  assert.equal((await fetch(base + '/..%2f..%2fserver.js')).status, 404);
  assert.equal((await fetch(base + '/%2e%2e/package.json')).status, 404);
});
