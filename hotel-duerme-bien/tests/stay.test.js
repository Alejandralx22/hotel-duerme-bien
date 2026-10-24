// Estadía: vista, fechas de inicio y término, y total por persona y noche (CP-32 y CP-33)
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { openDb } from '../src/db.js';
import { createApp } from '../src/app.js';
import { hashPassword, resetAttempts } from '../src/security.js';

let server, base, s;
const day = (n) => new Date(Date.now() + n * 86400000).toISOString().slice(0, 10);
const R = (b) => { let sum = 0, m = 2; for (let i = b.length - 1; i >= 0; i--) { sum += +b[i] * m; m = m === 7 ? 2 : m + 1; } const r = 11 - (sum % 11); return `${b}-${r === 11 ? '0' : r === 10 ? 'K' : r}`; };
beforeEach(() => resetAttempts());
before(async () => {
  const db = openDb(':memory:');
  db.prepare('INSERT INTO users (username,password_hash,role,created_at) VALUES (?,?,?,?)').run('enc', hashPassword('Encargado123'), 'encargado', 'now');
  server = createApp(db); await new Promise((r) => server.listen(0, r)); base = `http://localhost:${server.address().port}`;
  const l = await fetch(base + '/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'enc', password: 'Encargado123' }) });
  s = { cookie: l.headers.get('set-cookie').split(';')[0], csrf: (await l.json()).csrf };
});
after(() => server.close());
const call = async (m, u, b) => { const r = await fetch(base + u, { method: m, headers: { 'Content-Type': 'application/json', Cookie: s.cookie, 'X-CSRF-Token': s.csrf }, body: b ? JSON.stringify(b) : undefined }); return { status: r.status, body: await r.json() }; };
const mkRoom = async (n, cap, v = 'vista al mar') => (await call('POST', '/api/rooms', { number: n, capacity: cap, orientation: v })).body.id;
const people = (k, base0) => Array.from({ length: k }, (_, i) => ({ name: `Pasajero ${'ABCDEFGH'[i]}`, rut: R(String(base0 + i)), is_responsible: i === 0 }));

test('CP-32 estadía con fechas de inicio y término: total = pasajeros × noches × $40.000', async () => {
  const room = await mkRoom(1, 2);
  const ok = await call('POST', '/api/assignments', { room_ids: [room], passengers: people(2, 10000001), start_date: day(0), end_date: day(3) });
  assert.equal(ok.status, 201); assert.equal(ok.body.nights, 3); assert.equal(ok.body.total_cost, 240000); assert.equal(ok.body.cost_per_person, 120000);
  const g = (await call('GET', '/api/passengers')).body;
  assert.equal(g.length, 2); assert.ok(g.every((x) => x.start_date === day(0) && x.end_date === day(3) && x.nights === 3 && x.cost_per_person === 120000 && x.total_cost === 240000));
  const r2 = await mkRoom(2, 1); const bad = (b) => call('POST', '/api/assignments', { room_ids: [r2], passengers: people(1, 20000001), ...b });
  assert.equal((await bad({ start_date: day(1), end_date: day(1) })).status, 400); // mismo día: 0 noches
  assert.equal((await bad({ start_date: day(2), end_date: day(1) })).status, 400); // término anterior al inicio
  assert.equal((await bad({ start_date: '2026-02-30', end_date: '2026-03-02' })).status, 400); // fecha inexistente
  assert.equal((await bad({ start_date: day(-5), end_date: day(1) })).status, 400); // inicio en el pasado
  assert.equal((await bad({ start_date: day(0), end_date: day(400) })).status, 400); // más de 365 noches
  assert.equal((await bad({})).status, 400); // sin fechas
});
test('CP-33 la vista de la habitación es "al mar" o "a la ciudad"', async () => {
  assert.equal((await call('POST', '/api/rooms', { number: 11, capacity: 2, orientation: 'vista al mar' })).status, 201);
  assert.equal((await call('POST', '/api/rooms', { number: 12, capacity: 2, orientation: 'vista a la ciudad' })).status, 201);
  for (const v of ['norte', 'vista interior', 'techo', '']) assert.equal((await call('POST', '/api/rooms', { number: 13, capacity: 2, orientation: v })).status, 400);
  assert.deepEqual((await call('GET', '/api/rooms')).body.filter((r) => [11, 12].includes(r.number)).map((r) => r.orientation), ['vista al mar', 'vista a la ciudad']);
});
