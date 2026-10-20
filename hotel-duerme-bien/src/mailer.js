// Envío de correo sin dependencias: cliente SMTP mínimo (node:net / node:tls). Soporta SMTPS (465) y STARTTLS (587).
import net from 'node:net';
import tls from 'node:tls';

class Conn {
  constructor(sock) {
    this.sock = sock; this.buf = ''; this.q = []; this.err = null; this.closed = false;
    sock.on('data', (d) => { this.buf += d.toString('utf8'); this.flush(); });
    sock.on('error', (e) => { this.err = e; this.flush(); });
    sock.on('close', () => { this.closed = true; this.flush(); });
    sock.setTimeout(15_000, () => sock.destroy(new Error('SMTP: tiempo de espera agotado')));
  }
  take() { // respuesta completa: líneas hasta una con formato "250 texto"
    const lines = this.buf.split('\r\n'), done = lines.slice(0, -1);
    const i = done.findIndex((l) => /^\d{3}( |$)/.test(l));
    if (i < 0) return null;
    this.buf = lines.slice(i + 1).join('\r\n');
    return { code: +done[i].slice(0, 3), text: done.slice(0, i + 1).join('\n') };
  }
  flush() {
    while (this.q.length) {
      if (this.err) { this.q.shift().rej(this.err); continue; }
      const r = this.take();
      if (r) { this.q.shift().res(r); continue; }
      if (this.closed) { this.q.shift().rej(new Error('SMTP: conexión cerrada')); continue; }
      break;
    }
  }
  read() { return new Promise((res, rej) => { this.q.push({ res, rej }); this.flush(); }); }
  async expect(ok) { const r = await this.read(); if (!ok.includes(r.code)) throw new Error(`SMTP: respuesta ${r.code}`); return r; }
  async cmd(line, ok) { this.sock.write(line + '\r\n'); return this.expect(ok); }
}

export function smtpMailer({ host, port = 587, secure = false, starttls = true, user, pass, from }) {
  return async ({ to, subject, text }) => {
    if (/[\r\n]/.test(`${to}${subject}${from}`)) throw new Error('Cabecera de correo inválida'); // anti inyección de cabeceras
    let sock = secure ? tls.connect({ host, port, servername: host }) : net.connect({ host, port });
    let c = new Conn(sock);
    try {
      await c.expect([220]);
      let ehlo = await c.cmd('EHLO duermebien', [250]);
      if (!secure && starttls && /STARTTLS/i.test(ehlo.text)) {
        await c.cmd('STARTTLS', [220]);
        sock.removeAllListeners('data');
        sock = tls.connect({ socket: sock, servername: host }); c = new Conn(sock);
        ehlo = await c.cmd('EHLO duermebien', [250]);
      }
      if (user) await c.cmd('AUTH PLAIN ' + Buffer.from(`\0${user}\0${pass}`).toString('base64'), [235]);
      await c.cmd(`MAIL FROM:<${from}>`, [250]);
      await c.cmd(`RCPT TO:<${to}>`, [250, 251]);
      await c.cmd('DATA', [354]);
      const body = Buffer.from(text, 'utf8').toString('base64').match(/.{1,76}/g).join('\r\n');
      const head = [`From: Hotel Duerme Bien <${from}>`, `To: <${to}>`, `Subject: =?UTF-8?B?${Buffer.from(subject).toString('base64')}?=`,
        `Date: ${new Date().toUTCString()}`, 'MIME-Version: 1.0', 'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: base64'].join('\r\n');
      c.sock.write(`${head}\r\n\r\n${body}\r\n.\r\n`);
      await c.expect([250]);
      try { await c.cmd('QUIT', [221]); } catch { /* el correo ya fue aceptado */ }
    } finally { sock.destroy(); }
  };
}

// Sin SMTP configurado (desarrollo/demo) el código se imprime en la consola del servidor
export const consoleMailer = async ({ to, text }) => console.log(`[CORREO SIMULADO] Para: ${to}\n${text}`);

export function mailerFromEnv(env = process.env) {
  if (!env.SMTP_HOST) return consoleMailer;
  return smtpMailer({ host: env.SMTP_HOST, port: Number(env.SMTP_PORT ?? 587), secure: env.SMTP_SECURE === '1',
    user: env.SMTP_USER, pass: env.SMTP_PASS, from: env.SMTP_FROM ?? env.SMTP_USER });
}
