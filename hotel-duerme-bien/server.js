import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { openDb, audit } from './src/db.js';
import { hashPassword } from './src/security.js';
import { createApp } from './src/app.js';

const PORT = Number(process.env.PORT ?? 3000);

// En Vercel / serverless, la única carpeta con permisos de escritura efímera es /tmp
const DB_FILE = process.env.NODE_ENV === 'production' 
  ? '/tmp/hotel.db' 
  : (process.env.DB_FILE ?? './data/hotel.db');

fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
const db = openDb(DB_FILE);

// Inicialización de la BD
if (!db.prepare("SELECT 1 FROM users WHERE role='admin'").get()) {
  const pw = process.env.ADMIN_PASSWORD ?? randomBytes(9).toString('base64url') + '9a';
  db.prepare('INSERT INTO users (username,password_hash,role,created_at) VALUES (?,?,?,?)')
    .run('admin', hashPassword(pw), 'admin', new Date().toISOString());
  audit(db, 'system', 'ADMIN_SEED');
  console.log(process.env.ADMIN_PASSWORD ? 'Usuario admin creado.' : `Usuario admin creado. Contraseña inicial (guárdela): ${pw}`);
}

const app = createApp(db, { secure: process.env.NODE_ENV === 'production' });

// Solo se ejecuta el servidor si se corre directamente de forma local
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => console.log(`Hotel Duerme Bien en http://localhost:${PORT}`));
}

export default app;