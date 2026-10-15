import { randomBytes, scryptSync, timingSafeEqual, createHash } from 'node:crypto';

export class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
export const sha256 = (s) => createHash('sha256').update(s).digest('hex');

// A02 Fallas criptográficas: contraseñas con scrypt + sal única (nunca texto plano) - RNF01
export function hashPassword(pw) {
  const salt = randomBytes(16);
  return `scrypt$${salt.toString('hex')}$${scryptSync(pw, salt, 64).toString('hex')}`;
}
export function verifyPassword(pw, stored) {
  const [, saltHex, hashHex] = stored.split('$');
  const h = scryptSync(pw, Buffer.from(saltHex, 'hex'), 64);
  return timingSafeEqual(h, Buffer.from(hashHex, 'hex'));
}

// A04/A03: validación estricta de entradas
export function validPassword(pw) {
  return typeof pw === 'string' && pw.length >= 10 && pw.length <= 100 && /[A-Za-z]/.test(pw) && /\d/.test(pw);
}
export const validUsername = (u) => typeof u === 'string' && /^[a-z0-9._-]{3,30}$/i.test(u);
export const validName = (n) => typeof n === 'string' && /^[\p{L}][\p{L} .'-]{1,99}$/u.test(n.trim());

export function normalizeRut(rut) {
  if (typeof rut !== 'string') return null;
  const c = rut.replace(/[.\s]/g, '').toUpperCase();
  if (!/^\d{7,8}-[\dK]$/.test(c)) return null;
  const [body, dv] = c.split('-');
  let sum = 0, mul = 2;
  for (let i = body.length - 1; i >= 0; i--) { sum += +body[i] * mul; mul = mul === 7 ? 2 : mul + 1; }
  const r = 11 - (sum % 11);
  const expected = r === 11 ? '0' : r === 10 ? 'K' : String(r);
  return expected === dv ? c : null;
}

// A07 Fallas de autenticación: bloqueo de 15 min tras 5 fallos consecutivos, por usuario o por IP
const attempts = new Map();
const MAX = 5, LOCK_MS = 15 * 60 * 1000;
export function checkLock(keys) {
  if (keys.some((k) => (attempts.get(k)?.until ?? 0) > Date.now()))
    throw new HttpError(429, 'Demasiados intentos fallidos. Intente nuevamente en 15 minutos.');
}
export function registerFail(keys) {
  if (attempts.size > 10_000) attempts.clear(); // evita crecimiento ilimitado de memoria
  for (const k of keys) {
    const a = attempts.get(k) ?? { n: 0, until: 0 };
    a.n += 1;
    if (a.n >= MAX) { a.until = Date.now() + LOCK_MS; a.n = 0; }
    attempts.set(k, a);
  }
}
export const clearFails = (keys) => keys.forEach((k) => attempts.delete(k)); // "consecutivos": un acceso correcto reinicia
export const resetAttempts = () => attempts.clear(); // solo para pruebas
