import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { openDb, audit } from './src/db.js';
import { hashPassword } from './src/security.js';
import { createApp } from './src/app.js';
import { mailerFromEnv } from './src/mailer.js';

const PORT = Number(process.env.PORT ?? 3000);
const DB_FILE = process.env.DB_FILE ?? (process.env.NODE_ENV === 'production' || process.env.VERCEL === '1' ? '/tmp/hotel.db' : './data/hotel.db');
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
const app = createApp(db, { secure: process.env.NODE_ENV === 'production' || process.env.VERCEL === '1', trustProxy: process.env.TRUST_PROXY === '1' || process.env.VERCEL === '1',
  mfa, emailDomain: process.env.COMPANY_EMAIL_DOMAIN || null, mailer: mailerFromEnv() });

if (process.env.VERCEL !== '1') {
  app.listen(PORT, () => console.log(`Hotel Duerme Bien en http://localhost:${PORT}`));
  if (process.env.NODE_ENV === 'production') console.log('Modo producción local: publique el sistema detrás de HTTPS.');
}

// Adaptador para Vercel Functions: /api/* se dirige a este módulo y Vercel
// necesita una función exportada como handler.
export default function handler(req, res) {
  app.emit('request', req, res);
}
