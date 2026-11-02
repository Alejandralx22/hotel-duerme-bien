import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { openDb, audit } from './src/db.js';
import { hashPassword } from './src/security.js';
import { createApp } from './src/app.js';
import { mailerFromEnv } from './src/mailer.js';

const PORT = Number(process.env.PORT ?? 3000);
const DB_FILE = process.env.DB_FILE ?? (process.env.NODE_ENV === 'production' || process.env.VERCEL === '1' ? '/tmp/hotel.db' : './data/hotel.db');
fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
const db = openDb(DB_FILE);

const productionDemo = process.env.NODE_ENV === 'production' || !!process.env.VERCEL;

// En local conserva el arranque seguro con contraseña aleatoria. En Vercel crea una demo
// accesible para que las pantallas de habitaciones, pasajeros, cobros y salida estén visibles.
if (!db.prepare("SELECT 1 FROM users WHERE role='admin'").get()) {
  const pw = process.env.ADMIN_PASSWORD ?? (productionDemo ? 'Admin123456' : randomBytes(9).toString('base64url') + '9a');
  db.prepare('INSERT INTO users (username,password_hash,email,must_change_password,role,created_at) VALUES (?,?,?,?,?,?)')
    .run('admin', hashPassword(pw), (process.env.ADMIN_EMAIL ?? 'admin@duermebien.local').toLowerCase(), productionDemo ? 0 : 1, 'admin', new Date().toISOString());
  audit(db, { id: null, username: 'system' }, 'create_user', 'admin inicial');
  if (!productionDemo) console.log(process.env.ADMIN_PASSWORD ? 'Usuario admin creado.' : `Usuario admin creado. Contraseña inicial (guárdela): ${pw}`);
}
if (productionDemo && !db.prepare("SELECT 1 FROM users WHERE username='encargado'").get()) {
  const encargadoPassword = process.env.ENCARGADO_PASSWORD ?? 'Hotel123456';
  db.prepare('INSERT INTO users (username,password_hash,email,must_change_password,role,created_at) VALUES (?,?,?,?,?,?)')
    .run('encargado', hashPassword(encargadoPassword), 'encargado@duermebien.local', 0, 'encargado', new Date().toISOString());
  audit(db, { id: null, username: 'system' }, 'create_user', 'encargado de demostración');
}
if (productionDemo && db.prepare('SELECT COUNT(*) AS c FROM rooms WHERE deleted=0').get().c === 0) {
  const now = new Date().toISOString();
  const insert = db.prepare('INSERT INTO rooms (number,capacity,orientation,created_at) VALUES (?,?,?,?)');
  insert.run(101, 2, 'vista al mar', now);
  insert.run(102, 3, 'vista al mar', now);
  insert.run(103, 2, 'vista a la ciudad', now);
}
const mfa = !!process.env.SMTP_HOST && process.env.MFA_EMAIL !== '0'; // sin SMTP, la demo no bloquea el ingreso por correo

export const app = createApp(db, {
  secure: process.env.NODE_ENV === 'production' || process.env.VERCEL === '1',
  trustProxy: process.env.TRUST_PROXY === '1' || process.env.VERCEL === '1',
  mfa,
  emailDomain: process.env.COMPANY_EMAIL_DOMAIN || null,
  mailer: mailerFromEnv(),
  demo: productionDemo
});

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain && !process.env.VERCEL) {
  const PORT = Number(process.env.PORT ?? 3000);
  app.listen(PORT, () => console.log(`Hotel Duerme Bien en http://localhost:${PORT}`));
  if (process.env.NODE_ENV === 'production') console.log('Modo producción: publique el sistema detrás de HTTPS. Por http plano la cookie de sesión no se marca Secure.');
}

// Adaptador de Vercel para el servidor HTTP Node existente
export default function handler(req, res) {
  app.emit('request', req, res);
  return new Promise((resolve, reject) => {
    res.once?.('finish', resolve);
    res.once?.('close', resolve);
  });
}
