import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { openDb, audit } from './src/db.js';
import { hashPassword } from './src/security.js';
import { createApp } from './src/app.js';
import { mailerFromEnv } from './src/mailer.js';

const PORT = Number(process.env.PORT ?? 3000);
const DB_FILE = process.env.DB_FILE ?? './data/hotel.db';
fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
const db = openDb(DB_FILE);

// Sin credenciales por defecto (OWASP A07): si no hay admin, se crea con clave aleatoria o ADMIN_PASSWORD
if (!db.prepare("SELECT 1 FROM users WHERE role='admin'").get()) {
  const pw = process.env.ADMIN_PASSWORD ?? randomBytes(9).toString('base64url') + '9a';
  db.prepare('INSERT INTO users (username,password_hash,email,must_change_password,role,created_at) VALUES (?,?,?,?,?,?)')
    .run('admin', hashPassword(pw), (process.env.ADMIN_EMAIL ?? 'admin@duermebien.local').toLowerCase(), process.env.ADMIN_PASSWORD ? 0 : 1, 'admin', new Date().toISOString());
  audit(db, { id: null, username: 'system' }, 'create_user', 'admin inicial');
  console.log(process.env.ADMIN_PASSWORD ? 'Usuario admin creado.' : `Usuario admin creado. Contraseña inicial (guárdela): ${pw}`);
}
const mfa = process.env.MFA_EMAIL !== '0'; // verificación por correo activada por defecto
if (mfa && !process.env.SMTP_HOST) console.warn('AVISO: SMTP no configurado; los códigos de verificación se imprimen en esta consola.');
createApp(db, { secure: process.env.NODE_ENV === 'production', trustProxy: process.env.TRUST_PROXY === '1',
  mfa, emailDomain: process.env.COMPANY_EMAIL_DOMAIN || null, mailer: mailerFromEnv() })
  .listen(PORT, () => console.log(`Hotel Duerme Bien en http://localhost:${PORT}`));
if (process.env.NODE_ENV === 'production') console.log('Modo producción: publique el sistema detrás de HTTPS. Por http plano la cookie de sesión no se marca Secure.');
