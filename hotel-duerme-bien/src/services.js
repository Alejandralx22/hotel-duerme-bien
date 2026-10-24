// Capa de negocio: reglas del caso Hotel "Duerme Bien"
import { randomBytes, randomInt, timingSafeEqual } from 'node:crypto';
import { HttpError, normalizeRut, validName, hashPassword, verifyPassword, validPassword, validUsername, sha256 } from './security.js';
import { ORIENTATIONS, AUDIT_ACTIONS } from './db.js';

export const COST_PER_PASSENGER = 40000;

export function listRooms(db) {
  return db.prepare(`
    SELECT r.id, r.number, r.capacity, r.orientation,
      (SELECT COUNT(*) FROM passengers p JOIN assignments a ON a.id = p.assignment_id
        WHERE p.room_id = r.id AND a.checkout_at IS NULL) AS guests
    FROM rooms r WHERE r.deleted = 0 ORDER BY r.number`).all()
    .map((r) => ({ ...r, status: r.guests > 0 ? 'ocupada' : 'vacante' }));
}

export function createRoom(db, { number, capacity, orientation } = {}) {
  if (!Number.isInteger(number) || number < 1 || number > 9999) throw new HttpError(400, 'Número de habitación inválido');
  if (!Number.isInteger(capacity) || capacity < 1 || capacity > 10) throw new HttpError(400, 'Capacidad debe ser entre 1 y 10');
  if (!ORIENTATIONS.includes(orientation)) throw new HttpError(400, 'Orientación inválida');
  if (db.prepare('SELECT 1 FROM rooms WHERE number=? AND deleted=0').get(number)) throw new HttpError(409, 'El número de habitación ya existe');
  const r = db.prepare('INSERT INTO rooms (number,capacity,orientation,created_at) VALUES (?,?,?,?)')
    .run(number, capacity, orientation, new Date().toISOString());
  return { id: Number(r.lastInsertRowid), number, capacity, orientation };
}

export function deleteRoom(db, id) {
  const room = listRooms(db).find((r) => r.id === id);
  if (!room) throw new HttpError(404, 'Habitación no encontrada');
  if (room.guests > 0) throw new HttpError(409, 'No se puede eliminar: la habitación tiene pasajeros activos (RF07)');
  db.prepare('UPDATE rooms SET deleted=1 WHERE id=?').run(id); // baja lógica: conserva historial (RF08)
  return room;
}

// Fechas de la estadía (AAAA-MM-DD): inicio y término; el cobro es por persona y por noche
const DAY = 86400000;
const parseDay = (v) => {
  if (typeof v !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(v)) return null;
  const t = Date.parse(v + 'T00:00:00Z');
  return Number.isNaN(t) || new Date(t).toISOString().slice(0, 10) !== v ? null : t; // rechaza fechas inexistentes (30-02)
};
function stayNights(start_date, end_date) {
  const s = parseDay(start_date), e = parseDay(end_date);
  if (s === null || e === null) throw new HttpError(400, 'Ingrese fechas válidas de inicio y término');
  const today = parseDay(new Date().toISOString().slice(0, 10));
  if (s < today - DAY) throw new HttpError(400, 'La fecha de inicio no puede ser anterior a ayer');
  if (s > today + 730 * DAY) throw new HttpError(400, 'La fecha de inicio es demasiado lejana');
  const nights = Math.round((e - s) / DAY);
  if (nights < 1) throw new HttpError(400, 'La fecha de término debe ser posterior a la de inicio');
  if (nights > 365) throw new HttpError(400, 'La estadía no puede superar 365 noches');
  return nights;
}

export function assign(db, userId, { room_ids, passengers, start_date, end_date } = {}) {
  if (!Array.isArray(room_ids) || !room_ids.length || room_ids.length > 5 || !room_ids.every(Number.isInteger) || new Set(room_ids).size !== room_ids.length)
    throw new HttpError(400, 'Habitaciones inválidas');
  if (!Array.isArray(passengers) || !passengers.length || passengers.length > 50) throw new HttpError(400, 'Lista de pasajeros inválida');
  if (passengers.filter((p) => p?.is_responsible === true).length !== 1)
    throw new HttpError(400, 'Debe haber exactamente un pasajero responsable (RF14)');

  const people = passengers.map((p) => {
    const rut = normalizeRut(p?.rut);
    if (!validName(p?.name) || !rut) throw new HttpError(400, 'Nombre o RUT inválido');
    return { name: p.name.trim(), rut, resp: p.is_responsible === true };
  });
  if (new Set(people.map((p) => p.rut)).size !== people.length) throw new HttpError(400, 'RUT repetido en la solicitud');
  const hosted = db.prepare(`SELECT 1 FROM passengers p JOIN assignments a ON a.id=p.assignment_id
    WHERE a.checkout_at IS NULL AND p.rut=?`);
  if (people.some((p) => hosted.get(p.rut))) throw new HttpError(409, 'Un pasajero ya se encuentra hospedado');

  const nights = stayNights(start_date, end_date);
  const free = listRooms(db).filter((r) => r.guests === 0);
  const rooms = room_ids.map((id) => free.find((r) => r.id === id));
  if (rooms.some((r) => !r)) throw new HttpError(409, 'Alguna habitación no existe o está ocupada');
  const totalCap = rooms.reduce((s, r) => s + r.capacity, 0);
  if (people.length !== totalCap) throw new HttpError(422, `La cantidad de pasajeros (${people.length}) debe coincidir exactamente con la capacidad (${totalCap}) (RF10)`);
  if (rooms.length > 1 && people.length <= Math.max(...free.map((r) => r.capacity)))
    throw new HttpError(422, 'Solo se pueden reservar varias habitaciones si el grupo excede la habitación más grande disponible (RF13)');

  const total = people.length * nights * COST_PER_PASSENGER; // RF11: $40.000 por persona y por noche
  db.exec('BEGIN');
  try {
    const a = db.prepare('INSERT INTO assignments (room_ids,total_cost,start_date,end_date,nights,created_at,user_id) VALUES (?,?,?,?,?,?,?)')
      .run(JSON.stringify(rooms.map((r) => r.id)), total, start_date, end_date, nights, new Date().toISOString(), userId); // RF12
    const aid = Number(a.lastInsertRowid);
    const ins = db.prepare('INSERT INTO passengers (assignment_id,room_id,name,rut,is_responsible) VALUES (?,?,?,?,?)');
    let i = 0;
    for (const room of rooms) for (let k = 0; k < room.capacity; k++, i++)
      ins.run(aid, room.id, people[i].name, people[i].rut, people[i].resp ? 1 : 0);
    db.exec('COMMIT');
    return { id: aid, total_cost: total, passengers: people.length, nights, start_date, end_date, cost_per_person: nights * COST_PER_PASSENGER, rooms: rooms.map((r) => r.number) };
  } catch (e) { db.exec('ROLLBACK'); throw e; }
}

export function checkout(db, id) {
  const r = db.prepare('UPDATE assignments SET checkout_at=? WHERE id=? AND checkout_at IS NULL')
    .run(new Date().toISOString(), id);
  if (!r.changes) throw new HttpError(404, 'Asignación activa no encontrada');
}

export const listGuests = (db) => db.prepare(`
  SELECT p.name, p.rut, r.number AS room, p.is_responsible AS responsible,
         a.id AS assignment_id, a.total_cost, a.start_date, a.end_date, a.nights, a.created_at
  FROM passengers p JOIN assignments a ON a.id=p.assignment_id JOIN rooms r ON r.id=p.room_id
  WHERE a.checkout_at IS NULL ORDER BY r.number`).all()
  .map((r) => ({ ...r, cost_per_person: r.nights * COST_PER_PASSENGER }));

// Bitácora paginada y filtrable (por acción y/o usuario)
export function listAudit(db, q = {}) {
  const page = Math.max(1, parseInt(q.page, 10) || 1);
  const limit = Math.min(50, Math.max(1, parseInt(q.limit, 10) || 15));
  const where = [], args = [];
  if (q.action) {
    if (!AUDIT_ACTIONS.includes(q.action)) throw new HttpError(400, 'Acción de filtro inválida');
    where.push('action = ?'); args.push(q.action);
  }
  if (q.username) {
    where.push("username LIKE ? ESCAPE '\\'");
    args.push('%' + String(q.username).slice(0, 50).replace(/[\\%_]/g, '\\$&') + '%');
  }
  const w = where.length ? 'WHERE ' + where.join(' AND ') : '';
  const total = db.prepare(`SELECT COUNT(*) AS c FROM audit_log ${w}`).get(...args).c;
  const rows = db.prepare(`SELECT id, username, action, details, ip_address, timestamp FROM audit_log ${w}
    ORDER BY id DESC LIMIT ? OFFSET ?`).all(...args, limit, (page - 1) * limit);
  return { rows, total, page, pages: Math.max(1, Math.ceil(total / limit)) };
}

// ---------- Cuentas: usuarios, contraseñas y verificación por correo ----------
const POLICY = 'Contraseña: mínimo 10 caracteres con letras y números';
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}$/;
export const validEmail = (e, domain) => typeof e === 'string' && e.length <= 120 && EMAIL_RE.test(e)
  && (!domain || e.toLowerCase().endsWith('@' + domain.toLowerCase()));
export const maskEmail = (e) => e.replace(/^(.).*(@.*)$/, '$1***$2');

export function addUser(db, { username, password, email } = {}, { mfa = false, domain = null } = {}) {
  if (!validUsername(username)) throw new HttpError(400, 'Usuario inválido (3-30 caracteres alfanuméricos . _ -)');
  if (!validPassword(password)) throw new HttpError(400, POLICY);
  const has = email !== undefined && email !== null && email !== '';
  if ((has || mfa) && !validEmail(email, domain))
    throw new HttpError(400, domain ? `Ingrese un correo de la empresa (@${domain})` : 'Ingrese un correo válido');
  if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(username)) throw new HttpError(409, 'El usuario ya existe');
  const mail = has ? email.trim().toLowerCase() : null;
  if (mail && db.prepare('SELECT 1 FROM users WHERE email = ?').get(mail)) throw new HttpError(409, 'Ese correo ya está registrado');
  // la clave inicial es temporal: el usuario debe cambiarla en su primer ingreso
  db.prepare('INSERT INTO users (username,password_hash,email,must_change_password,role,created_at) VALUES (?,?,?,?,?,?)')
    .run(username, hashPassword(password), mail, 1, 'encargado', new Date().toISOString());
  return { username, email: mail, role: 'encargado' };
}

export function resetPassword(db, id, password) {
  const t = db.prepare('SELECT id, username, role FROM users WHERE id = ?').get(id);
  if (!t) throw new HttpError(404, 'Usuario no encontrado');
  if (t.role !== 'encargado') throw new HttpError(400, 'Solo se pueden restablecer claves de Encargados');
  if (!validPassword(password)) throw new HttpError(400, POLICY);
  db.prepare('UPDATE users SET password_hash = ?, must_change_password = 1 WHERE id = ?').run(hashPassword(password), id);
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(id); // cierra sus sesiones abiertas
  db.prepare('DELETE FROM login_challenges WHERE user_id = ?').run(id);
  return t;
}

export function changePassword(db, session, { current_password, new_password } = {}) {
  const u = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(session.id);
  if (typeof current_password !== 'string' || !verifyPassword(current_password, u.password_hash)) {
    const e = new HttpError(400, 'La contraseña actual es incorrecta'); e.wrongCurrent = true; throw e;
  }
  if (!validPassword(new_password)) throw new HttpError(400, POLICY);
  if (new_password === current_password) throw new HttpError(400, 'La nueva contraseña debe ser distinta a la actual');
  db.prepare('UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?').run(hashPassword(new_password), session.id);
  db.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?').run(session.id, session.token_hash); // cierra las demás sesiones
}

const CODE_TTL = 10 * 60 * 1000, RESEND_MS = 60 * 1000, MAX_TRIES = 5, MAX_RESENDS = 3;
async function sendCode(db, mailer, user, tokenHash, code) {
  try {
    await mailer({ to: user.email, subject: 'Código de verificación - Hotel Duerme Bien',
      text: `Su código de verificación es ${code}.\nVence en 10 minutos. Si usted no intentó ingresar, ignore este mensaje y avise al administrador.` });
  } catch (e) {
    console.error('Error enviando el correo:', e.message);
    db.prepare('DELETE FROM login_challenges WHERE token_hash = ?').run(tokenHash);
    throw new HttpError(502, 'No se pudo enviar el código al correo. Intente nuevamente.');
  }
}
const newCode = () => { const salt = randomBytes(8).toString('hex'), code = String(randomInt(0, 1_000_000)).padStart(6, '0'); return { salt, code, hash: sha256(salt + code) }; };

export async function startChallenge(db, user, mailer) {
  const token = randomBytes(32).toString('hex'), { salt, code, hash } = newCode(), now = Date.now();
  db.prepare('DELETE FROM login_challenges WHERE user_id = ? OR expires_at < ?').run(user.id, now);
  db.prepare('INSERT INTO login_challenges (token_hash,user_id,code_salt,code_hash,expires_at,last_sent_at) VALUES (?,?,?,?,?,?)')
    .run(sha256(token), user.id, salt, hash, now + CODE_TTL, now);
  await sendCode(db, mailer, user, sha256(token), code);
  return token;
}
export const findChallenge = (db, token) => (typeof token === 'string' && /^[a-f0-9]{64}$/.test(token)
  ? db.prepare(`SELECT c.*, u.username, u.email, u.role, u.must_change_password FROM login_challenges c
      JOIN users u ON u.id = c.user_id WHERE c.token_hash = ?`).get(sha256(token)) ?? null : null);

export function verifyChallenge(db, row, code) {
  const bad = () => new HttpError(401, 'Código inválido o vencido'), del = () => db.prepare('DELETE FROM login_challenges WHERE token_hash = ?').run(row.token_hash);
  if (!row || row.expires_at < Date.now()) { if (row) del(); throw bad(); }
  if (row.attempts + 1 >= MAX_TRIES) del(); else db.prepare('UPDATE login_challenges SET attempts = attempts + 1 WHERE token_hash = ?').run(row.token_hash);
  const c = String(code ?? '');
  if (!/^\d{6}$/.test(c) || !timingSafeEqual(Buffer.from(sha256(row.code_salt + c), 'hex'), Buffer.from(row.code_hash, 'hex'))) throw bad();
  del(); // el código es de un solo uso
  return { id: row.user_id, username: row.username, role: row.role, must_change_password: row.must_change_password };
}

export async function resendChallenge(db, row, mailer) {
  if (!row || row.expires_at < Date.now()) throw new HttpError(401, 'La verificación venció. Inicie sesión nuevamente.');
  if (Date.now() - row.last_sent_at < RESEND_MS) throw new HttpError(429, 'Espere un minuto antes de pedir otro código.');
  if (row.resends >= MAX_RESENDS) throw new HttpError(429, 'Límite de reenvíos alcanzado. Inicie sesión nuevamente.');
  const { salt, code, hash } = newCode(), now = Date.now();
  db.prepare('UPDATE login_challenges SET code_salt=?, code_hash=?, expires_at=?, attempts=0, resends=resends+1, last_sent_at=? WHERE token_hash=?')
    .run(salt, hash, now + CODE_TTL, now, row.token_hash);
  await sendCode(db, mailer, row, row.token_hash, code);
}
