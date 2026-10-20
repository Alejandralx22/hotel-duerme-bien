// Cuentas: verificación por correo (2FA), cambio y restablecimiento de contraseña. CP-21 a CP-27
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { openDb } from '../src/db.js';
import { createApp } from '../src/app.js';
import { hashPassword, resetAttempts } from '../src/security.js';
import { smtpMailer } from '../src/mailer.js';

let server, base, db; const sent = [];
const PW = 'Admin12345678', EPW = 'Encargado1234', DOM = 'duermebien.cl';
beforeEach(() => resetAttempts());
before(async () => {
  db = openDb(':memory:');
  const ins = db.prepare('INSERT INTO users (username,password_hash,email,role,created_at) VALUES (?,?,?,?,?)');
  ins.run('admin', hashPassword(PW), `admin@${DOM}`, 'admin', 'now');
  ins.run('enc', hashPassword(EPW), `enc@${DOM}`, 'encargado', 'now');
  server = createApp(db, { mfa: true, emailDomain: DOM, mailer: async (m) => sent.push(m) });
  await new Promise((r) => server.listen(0, r)); base = `http://localhost:${server.address().port}`;
});
after(() => server.close());

async function call(method, url, body, s) {
  const r = await fetch(base + url, { method, headers: { 'Content-Type': 'application/json', ...(s ? { Cookie: s.cookie, 'X-CSRF-Token': s.csrf } : {}) }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, body: await r.json(), headers: r.headers };
}
const lastCode = () => /\b(\d{6})\b/.exec(sent.at(-1).text)[1];
const step1 = (u, p) => call('POST', '/api/login', { username: u, password: p });
async function login(u, p) { // flujo completo: contraseña + código del correo
  const a = await step1(u, p); assert.equal(a.status, 200, JSON.stringify(a.body));
  const v = await call('POST', '/api/login/verify', { challenge: a.body.challenge, code: lastCode() });
  assert.equal(v.status, 200); return { ...v, cookie: v.headers.get('set-cookie').split(';')[0], csrf: v.body.csrf };
}
const wrongCode = () => (lastCode() === '000000' ? '111111' : '000000');

test('CP-21 (A07) login en dos pasos: sin cookie hasta validar el código del correo', async () => {
  const n = sent.length, a = await step1('enc', EPW);
  assert.equal(a.body.mfa, true); assert.ok(a.body.challenge); assert.equal(a.body.email_hint, 'e***@' + DOM);
  assert.equal(a.headers.get('set-cookie'), null); assert.equal(sent.length, n + 1); assert.equal(sent.at(-1).to, `enc@${DOM}`);
  assert.equal((await call('POST', '/api/login/verify', { challenge: a.body.challenge, code: wrongCode() })).status, 401);
  const ok = await call('POST', '/api/login/verify', { challenge: a.body.challenge, code: lastCode() });
  assert.equal(ok.status, 200); assert.match(ok.headers.get('set-cookie'), /HttpOnly/);
  assert.equal((await call('POST', '/api/login/verify', { challenge: a.body.challenge, code: lastCode() })).status, 401); // un solo uso
});
test('CP-22 códigos erróneos repetidos bloquean la cuenta (429)', async () => {
  const a = await step1('enc', EPW), bad = wrongCode();
  for (let i = 0; i < 5; i++) assert.equal((await call('POST', '/api/login/verify', { challenge: a.body.challenge, code: bad })).status, 401);
  assert.equal((await call('POST', '/api/login/verify', { challenge: a.body.challenge, code: lastCode() })).status, 429);
});
test('CP-23 reenvío con espera, y código vencido rechazado', async () => {
  const a = await step1('enc', EPW), n = sent.length;
  assert.equal((await call('POST', '/api/login/resend', { challenge: a.body.challenge })).status, 429); // muy pronto
  db.prepare('UPDATE login_challenges SET last_sent_at = 0').run();
  assert.equal((await call('POST', '/api/login/resend', { challenge: a.body.challenge })).status, 200); assert.equal(sent.length, n + 1);
  db.prepare('UPDATE login_challenges SET expires_at = 0').run();
  assert.equal((await call('POST', '/api/login/verify', { challenge: a.body.challenge, code: lastCode() })).status, 401);
});
test('CP-24 cambio de contraseña: valida la actual, la política y cierra las otras sesiones', async () => {
  const s = await login('enc', EPW), other = await login('enc', EPW);
  const chg = (cur, nw) => call('POST', '/api/password', { current_password: cur, new_password: nw }, s);
  assert.equal((await chg('incorrecta123', 'NuevaClave123')).status, 400);
  assert.equal((await chg(EPW, '123')).status, 400);
  assert.equal((await chg(EPW, EPW)).status, 400);
  assert.equal((await chg(EPW, 'NuevaClave123')).status, 200);
  assert.equal((await call('GET', '/api/me', null, other)).status, 401); // la otra sesión se cerró
  assert.equal((await call('GET', '/api/me', null, s)).status, 200);
  assert.equal((await step1('enc', EPW)).status, 401); // la clave anterior ya no sirve
  assert.equal((await step1('enc', 'NuevaClave123')).status, 200);
  const a = await login('admin', PW);
  assert.ok((await call('GET', '/api/audit?action=change_password', null, a)).body.total >= 1);
  db.prepare('UPDATE users SET password_hash = ? WHERE username = ?').run(hashPassword(EPW), 'enc');
});
test('CP-25 usuario nuevo: exige correo de la empresa y debe cambiar la clave temporal', async () => {
  const a = await login('admin', PW), mk = (b) => call('POST', '/api/users', b, a);
  assert.equal((await mk({ username: 'nueva.rec', password: 'Temporal12345' })).status, 400); // sin correo
  assert.equal((await mk({ username: 'nueva.rec', password: 'Temporal12345', email: 'x@gmail.com' })).status, 400); // fuera de la empresa
  assert.equal((await mk({ username: 'nueva.rec', password: 'Temporal12345', email: `Nueva@${DOM}` })).status, 201);
  assert.equal((await mk({ username: 'otra.rec', password: 'Temporal12345', email: `nueva@${DOM}` })).status, 409); // correo repetido
  const s = await login('nueva.rec', 'Temporal12345');
  assert.equal(s.body.must_change, true);
  const blocked = await call('GET', '/api/rooms', null, s); assert.equal(blocked.status, 403); assert.equal(blocked.body.code, 'must_change_password');
  assert.equal((await call('POST', '/api/password', { current_password: 'Temporal12345', new_password: 'DefinitivaClave1' }, s)).status, 200);
  assert.equal((await call('GET', '/api/rooms', null, s)).status, 200);
});
test('CP-26 el Administrador restablece la clave de un Encargado (y solo él)', async () => {
  const a = await login('admin', PW), enc = await login('enc', EPW);
  const id = db.prepare("SELECT id FROM users WHERE username='enc'").get().id, adminId = db.prepare("SELECT id FROM users WHERE username='admin'").get().id;
  assert.equal((await call('POST', `/api/users/${id}/reset-password`, { password: 'Temporal98765' }, enc)).status, 403);
  assert.equal((await call('POST', `/api/users/${adminId}/reset-password`, { password: 'Temporal98765' }, a)).status, 400);
  assert.equal((await call('POST', `/api/users/${id}/reset-password`, { password: '123' }, a)).status, 400);
  assert.equal((await call('POST', `/api/users/${id}/reset-password`, { password: 'Temporal98765' }, a)).status, 200);
  assert.equal((await call('GET', '/api/me', null, enc)).status, 401); // sus sesiones se cerraron
  assert.equal((await login('enc', 'Temporal98765')).body.must_change, true);
  assert.equal((await call('GET', '/api/audit?action=reset_password', null, a)).body.total, 1);
});
test('CP-27 el mailer SMTP entrega el código a un servidor de correo (servidor falso local)', async () => {
  const got = {}; const srv = net.createServer((sock) => {
    let data = false, buf = ''; sock.write('220 fake\r\n');
    sock.on('data', (d) => { buf += d; let i;
      while ((i = buf.indexOf('\r\n')) >= 0) { const l = buf.slice(0, i); buf = buf.slice(i + 2);
        if (data) { if (l === '.') { data = false; sock.write('250 queued\r\n'); } else got.raw = (got.raw ?? '') + l + '\n'; continue; }
        if (/^EHLO/i.test(l)) sock.write('250-fake\r\n250 8BITMIME\r\n');
        else if (/^MAIL/i.test(l)) { got.from = l; sock.write('250 ok\r\n'); }
        else if (/^RCPT/i.test(l)) { got.to = l; sock.write('250 ok\r\n'); }
        else if (/^DATA/i.test(l)) { data = true; sock.write('354 go\r\n'); }
        else if (/^QUIT/i.test(l)) sock.end('221 bye\r\n'); } }); });
  await new Promise((r) => srv.listen(0, r));
  await smtpMailer({ host: '127.0.0.1', port: srv.address().port, starttls: false, from: `no-reply@${DOM}` })({ to: `enc@${DOM}`, subject: 'Código', text: 'Su código es 482913' });
  assert.match(got.to, new RegExp(`<enc@${DOM}>`)); assert.match(got.from, /no-reply@/);
  assert.match(Buffer.from(got.raw.split('\n\n')[1].replace(/\n/g, ''), 'base64').toString('utf8'), /482913/);
  await assert.rejects(smtpMailer({ host: '127.0.0.1', port: srv.address().port, starttls: false, from: 'a@b.cl' })({ to: 'x@y.cl\r\nBcc: z@y.cl', subject: 's', text: 't' })); // inyección de cabeceras
  srv.close();
});
