// Cliente SPA. Los datos dinámicos se escriben solo con createElement/textContent (nunca innerHTML) - OWASP A03
const ROLE = { admin: 'Administrador', encargado: 'Encargado de Hotel' };
const ORIENTATIONS = ['vista al mar', 'vista a la ciudad'];
const ACTIONS = { login: 'Inicio de sesión', logout: 'Cierre de sesión', create_user: 'Creación de usuario', create_room: 'Alta de habitación',
  delete_room: 'Baja de habitación', assign_passengers: 'Asignación de pasajeros', checkout: 'Check-out',
  change_password: 'Cambio de contraseña', reset_password: 'Restablecimiento de contraseña' };
const COST = 40000;
let session = null, tab = 'rooms', timer = null, resume = null, cfg = { mfa: false, email_domain: null };
const audit = { page: 1, action: '', username: '' };
const $ = (id) => document.getElementById(id);
const app = $('app');

function h(tag, props = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'class') e.className = v;
    else if (k === 'disabled') e.disabled = !!v;
    else e.setAttribute(k, v);
  }
  for (const c of kids.flat()) if (c !== null && c !== undefined && c !== false) e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return e;
}
async function api(method, url, body) {
  let r;
  try {
    r = await fetch(url, { method, credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', ...(session ? { 'X-CSRF-Token': session.csrf } : {}) },
      body: body ? JSON.stringify(body) : undefined });
  } catch { throw new Error('No se pudo conectar con el servidor'); }
  const data = await r.json().catch(() => ({}));
  if (r.status === 401 && session) { resume = tab; stopTimer(); session = null; loginView('Su sesión expiró. Ingrese nuevamente: volverá a esta pantalla y lo que escribió se conserva.'); throw new Error('Sesión expirada'); }
  if (!r.ok) { const err = new Error(data.error || 'Error inesperado'); err.status = r.status; err.code = data.code; throw err; }
  return data;
}
const stopTimer = () => { if (timer) clearInterval(timer); timer = null; };
const note = (el, text, kind = 'err') => el.replaceChildren(h('div', { class: 'msg ' + (kind === 'ok' ? 'okm' : kind), role: 'alert' }, text));
const table = (cols, rows) => h('div', { class: 'tw' }, h('table', {}, h('thead', {}, h('tr', {}, cols.map(([t]) => h('th', {}, t)))),
  h('tbody', {}, rows.map((r) => h('tr', {}, cols.map(([, f]) => h('td', {}, f(r))))))));
const stateCell = (s) => [h('span', { class: 'dot ' + s }), h('span', { class: 'badge ' + s }, s === 'vacante' ? 'Vacante' : 'Ocupada')];
// Borradores: lo escrito en los formularios no se pierde si hay un error o se cambia de pestaña (las contraseñas nunca se guardan)
const drafts = {};
function keep(key, input) {
  if (drafts[key] !== undefined) input.value = drafts[key];
  const save = () => { drafts[key] = input.value; };
  input.addEventListener('input', save); input.addEventListener('change', save);
  return input;
}
const clearDrafts = (prefix) => Object.keys(drafts).filter((k) => k.startsWith(prefix)).forEach((k) => delete drafts[k]);
const cap = (t) => (t ? t[0].toUpperCase() + t.slice(1) : '');
const day = (iso) => iso.split('-').reverse().join('-');
const addDays = (iso, n) => new Date(Date.parse(iso) + n * 86400000).toISOString().slice(0, 10);
const todayISO = () => { const d = new Date(); return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 10); };
const money = (n) => '$' + n.toLocaleString('es-CL');
const when = (iso) => new Date(iso).toLocaleString('es-CL');
const whenShort = (iso) => new Date(iso).toLocaleString('es-CL', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false });

// Lista de requisitos de contraseña que se marcan mientras se escribe (el servidor valida igual)
function pwRules(input) {
  const rules = [['Mínimo 10 caracteres', (v) => v.length >= 10], ['Incluye letras', (v) => /[A-Za-z]/.test(v)], ['Incluye números', (v) => /\d/.test(v)]];
  const ul = h('ul', { class: 'rules' }, rules.map(([t]) => h('li', { class: 'bad' }, '○ ' + t)));
  input.addEventListener('input', () => rules.forEach(([t, f], i) => { const ok = f(input.value); ul.children[i].className = ok ? 'ok' : 'bad'; ul.children[i].textContent = (ok ? '✓ ' : '○ ') + t; }));
  return ul;
}

// Validador de RUT (módulo 11), solo para dar retroalimentación inmediata; el servidor valida de nuevo
function rutNorm(v) {
  const c = String(v).replace(/[.\s]/g, '').toUpperCase();
  if (!/^\d{7,8}-[\dK]$/.test(c)) return null;
  const [b, dv] = c.split('-'); let s = 0, m = 2;
  for (let i = b.length - 1; i >= 0; i--) { s += +b[i] * m; m = m === 7 ? 2 : m + 1; }
  const r = 11 - (s % 11);
  return (r === 11 ? '0' : r === 10 ? 'K' : String(r)) === dv ? c : null;
}

function loginView(info) {
  stopTimer(); $('who').replaceChildren();
  const msg = h('div'); if (info) note(msg, info, 'ok');
  const u = h('input', { placeholder: 'Usuario', autocomplete: 'username', 'aria-label': 'Usuario' });
  const p = h('input', { type: 'password', placeholder: 'Contraseña', autocomplete: 'current-password', 'aria-label': 'Contraseña' });
  const finish = async (sess, target) => {
    // Comprueba que el navegador conservó la cookie; si no, evita el bucle ingreso → cierre y explica el motivo
    const alive = await fetch('/api/me', { credentials: 'same-origin' }).then((r) => r.ok).catch(() => false);
    if (!alive) return note(target, '⚠️ El servidor aceptó su clave, pero el navegador no conservó la sesión (cookie). Suele pasar si el sistema se abre por http y no por https, o si el navegador bloquea las cookies. Abra el sistema por https o permita las cookies.', 'lock');
    const allowed = sess.role === 'admin' ? ['users', 'audit', 'password'] : ['dashboard', 'rooms', 'assign', 'password'];
    session = sess; tab = resume && allowed.includes(resume) ? resume : sess.role === 'admin' ? 'users' : 'dashboard'; resume = null; render();
  };
  const codeStep = (res) => { // segundo paso: código enviado al correo de la empresa
    const m2 = h('div'), code = h('input', { placeholder: 'Código de 6 dígitos', inputmode: 'numeric', maxlength: '6', autocomplete: 'one-time-code', 'aria-label': 'Código de verificación' });
    const verify = async () => { try { await finish(await api('POST', '/api/login/verify', { challenge: res.challenge, code: code.value.trim() }), m2); }
      catch (e) { note(m2, e.status === 429 ? '🔒 ' + e.message : e.message, e.status === 429 ? 'lock' : 'err'); } };
    const resend = async () => { try { await api('POST', '/api/login/resend', { challenge: res.challenge }); note(m2, 'Enviamos un nuevo código a su correo.', 'ok'); }
      catch (e) { note(m2, e.message, e.status === 429 ? 'lock' : 'err'); } };
    code.addEventListener('keydown', (e) => e.key === 'Enter' && verify());
    app.replaceChildren(h('section', { class: 'login' }, h('h2', {}, 'Verificación en dos pasos'),
      h('p', { class: 'hint' }, `Enviamos un código de 6 dígitos al correo ${res.email_hint}. Vence en 10 minutos.`), code,
      h('button', { onclick: verify }, 'Verificar'), h('button', { class: 'sec', onclick: resend }, 'Reenviar código'), h('button', { class: 'sec', onclick: () => loginView() }, 'Volver'), m2));
    code.focus();
  };
  const go = async () => {
    try { const res = await api('POST', '/api/login', { username: u.value, password: p.value }); if (res.mfa) codeStep(res); else await finish(res, msg); }
    catch (e) {
      if (e.status === 429) note(msg, '🔒 Acceso bloqueado por 15 minutos tras 5 intentos fallidos consecutivos. Intente más tarde.', 'lock');
      else note(msg, e.message);
    }
  };
  p.addEventListener('keydown', (e) => e.key === 'Enter' && go());
  app.replaceChildren(h('section', { class: 'login' }, h('h2', {}, 'Acceso del personal'),
    h('p', { class: 'hint' }, 'Solo personal autorizado. No existe registro público.'), u, p, h('button', { onclick: go }, 'Ingresar'), msg));
  u.focus();
}

async function render() {
  stopTimer();
  $('who').replaceChildren(h('span', { class: 'user' }, session.username), h('span', { class: 'badge role-' + session.role }, ROLE[session.role]),
    h('button', { onclick: async () => { try { await api('POST', '/api/logout'); } catch { /* igual se limpia la sesión local */ } session = null; resume = null; audit.page = 1; audit.action = ''; audit.username = ''; loginView('Sesión cerrada correctamente.'); } }, 'Cerrar sesión'));
  const tabs = session.role === 'admin'
    ? [['users', 'Usuarios'], ['audit', 'Auditoría']]
    : [['dashboard', 'Estado del Hotel'], ['rooms', 'Habitaciones'], ['assign', 'Asignación / Check-in']];
  if (session.must_change) tab = 'password'; // clave temporal: no puede usar el sistema hasta cambiarla
  else tabs.push(['password', 'Cambiar contraseña']);
  const body = h('div');
  const plain = location.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(location.hostname); // conexión sin cifrar
  app.replaceChildren(...(plain ? [h('div', { class: 'msg lock' }, '⚠️ Conexión sin cifrar (http). Úsela solo para pruebas; en producción use https.')] : []), h('nav', {}, (session.must_change ? [['password', 'Cambiar contraseña']] : tabs).map(([k, t]) => h('button', { class: k === tab ? 'on' : '', onclick: () => { tab = k; render(); } }, t))), body);
  try { await views[tab](body); } catch (e) { if (session) note(body, e.message); }
}

const views = {
  // RF15 y RF16: estado de habitaciones y pasajeros hospedados
  async dashboard(body) {
    const [rooms, guests] = await Promise.all([api('GET', '/api/rooms'), api('GET', '/api/passengers')]), msg = h('div');
    const vac = rooms.filter((r) => r.status === 'vacante').length;
    const tile = (cls, n, label) => h('div', { class: 'tile ' + cls }, h('b', {}, n), label);
    const roomCols = [['N°', (r) => r.number], ['Capacidad', (r) => r.capacity], ['Vista', (r) => cap(r.orientation)], ['Estado', (r) => stateCell(r.status)], ['Huéspedes', (r) => r.guests]];
    const guestCols = [['Hab.', (r) => r.room], ['Pasajero', (r) => r.name], ['RUT', (r) => r.rut],
      ['Responsable', (r) => (r.responsible ? h('span', { class: 'badge resp' }, 'Responsable') : '')],
      ['Inicio', (r) => day(r.start_date)], ['Término', (r) => day(r.end_date)], ['Noches', (r) => r.nights],
      ['Por persona', (r) => money(r.cost_per_person)], ['Registrado', (r) => whenShort(r.created_at)],
      ['Total del grupo', (r) => (r.responsible ? h('b', {}, money(r.total_cost)) : '')],
      ['', (r) => (r.responsible ? h('button', { class: 'out', title: 'Libera todas las habitaciones del grupo', onclick: async () => {
        if (!confirm(`¿Confirmar check-out del grupo de ${r.name}? Se liberarán sus habitaciones.`)) return;
        try { await api('POST', `/api/assignments/${r.assignment_id}/checkout`); render(); } catch (e) { note(msg, e.message); } } }, 'Check-out') : '')]];
    body.replaceChildren(
      h('div', { class: 'tiles' }, tile('vac', vac, 'Habitaciones vacantes'), tile('occ', rooms.length - vac, 'Habitaciones ocupadas'), tile('', guests.length, 'Pasajeros hospedados')),
      h('section', {}, h('h2', {}, 'Estado de habitaciones'), rooms.length ? table(roomCols, rooms) : h('p', {}, 'No hay habitaciones registradas.')),
      h('section', {}, h('h2', {}, 'Pasajeros hospedados'), msg, guests.length ? table(guestCols, guests) : h('p', {}, 'No hay pasajeros hospedados.')));
  },

  // RF06, RF07, RF08: alta y baja lógica de habitaciones
  async rooms(body) {
    const rooms = await api('GET', '/api/rooms'), msg = h('div'), msg2 = h('div');
    const num = keep('room.num', h('input', { type: 'number', placeholder: 'N° de habitación', min: 1, max: 9999, 'aria-label': 'Número de habitación' }));
    const capi = keep('room.cap', h('input', { type: 'number', placeholder: 'Capacidad (1 a 10)', min: 1, max: 10, 'aria-label': 'Capacidad' }));
    const ori = keep('room.ori', h('select', { 'aria-label': 'Vista' }, ORIENTATIONS.map((o) => h('option', { value: o }, cap(o)))));
    const add = async () => { try { await api('POST', '/api/rooms', { number: +num.value, capacity: +capi.value, orientation: ori.value }); clearDrafts('room.'); render(); } catch (e) { note(msg, e.message); } };
    const cols = [['N°', (r) => r.number], ['Capacidad', (r) => r.capacity], ['Vista', (r) => cap(r.orientation)], ['Estado', (r) => stateCell(r.status)],
      ['', (r) => h('button', { class: 'del', onclick: async () => { if (!confirm(`¿Eliminar la habitación ${r.number}?`)) return;
        try { await api('DELETE', '/api/rooms/' + r.id); render(); } catch (e) { note(msg2, e.message); } } }, 'Eliminar')]];
    body.replaceChildren(
      h('section', {}, h('h2', {}, 'Registrar habitación'), num, capi, ori, h('button', { onclick: add }, 'Agregar habitación'), msg),
      h('section', {}, h('h2', {}, 'Habitaciones activas'),
        h('p', { class: 'hint' }, 'Una habitación con pasajeros activos no se puede eliminar: primero haga el check-out. La baja es lógica y conserva el historial.'),
        msg2, rooms.length ? table(cols, rooms) : h('p', {}, 'No hay habitaciones registradas.')));
  },

  // RF09 a RF14: asignación de pasajeros / check-in (con fechas de inicio y término)
  async assign(body) {
    const free = (await api('GET', '/api/rooms')).filter((r) => r.status === 'vacante'), msg = h('div');
    const picks = free.map((r) => ({ r, cb: h('input', { type: 'checkbox' }) }));
    const saved = drafts['ci.rooms'] ?? []; picks.forEach((p) => { p.cb.checked = saved.includes(p.r.id); });
    const d0 = todayISO();
    const start = keep('ci.start', h('input', { type: 'date', min: addDays(d0, -1), 'aria-label': 'Fecha de inicio' })); if (!start.value) start.value = d0;
    const end = keep('ci.end', h('input', { type: 'date', 'aria-label': 'Fecha de término' })); if (!end.value) end.value = addDays(d0, 1);
    const rowsBox = h('div'), sum = h('div', { class: 'sum' }), people = [];
    const need = () => picks.filter((p) => p.cb.checked).reduce((s, p) => s + p.r.capacity, 0);
    const nights = () => Math.round((Date.parse(end.value) - Date.parse(start.value)) / 86400000);
    const checkRuts = () => { // retroalimentación visual: RUT válido / inválido / repetido (con o sin puntos)
      const seen = new Map(); people.forEach((p) => { const n = rutNorm(p.rut.value); if (n) seen.set(n, (seen.get(n) ?? 0) + 1); });
      people.forEach((p) => {
        const v = p.rut.value.trim(), n = rutNorm(v);
        p.hint.className = !v ? 'hint' : n && seen.get(n) === 1 ? 'vok' : 'vbad';
        p.hint.textContent = !v ? 'Formato 12345678-5' : !n ? '✗ RUT inválido' : seen.get(n) > 1 ? '✗ RUT repetido' : '✓ RUT válido';
      });
    };
    const addRow = () => {
      const i = people.length, n = i + 1;
      const name = keep(`ci.p${i}.name`, h('input', { type: 'text', placeholder: `Pasajero ${n}: nombre completo`, 'aria-label': `Nombre del pasajero ${n}` }));
      const rut = keep(`ci.p${i}.rut`, h('input', { type: 'text', placeholder: 'RUT (12345678-5)', 'aria-label': `RUT del pasajero ${n}` }));
      const resp = h('input', { type: 'radio', name: 'resp', 'aria-label': `Responsable: pasajero ${n}` });
      resp.addEventListener('change', () => { drafts['ci.resp'] = i; });
      const hint = h('span', { class: 'hint' }, 'Formato 12345678-5');
      rut.addEventListener('input', checkRuts);
      const el = h('div', { class: 'prow' }, h('label', {}, resp, ' Responsable'), name, rut, hint);
      people.push({ name, rut, resp, hint, el }); rowsBox.append(el);
    };
    const sync = () => { // un formulario por pasajero según la capacidad seleccionada; el cobro es por persona y por noche
      const n = need(), k = nights();
      drafts['ci.rooms'] = picks.filter((p) => p.cb.checked).map((p) => p.r.id);
      while (people.length < n) addRow();
      while (people.length > n) people.pop().el.remove();
      if (people.length && !people.some((p) => p.resp.checked)) (people[drafts['ci.resp']] ?? people[0]).resp.checked = true;
      checkRuts();
      if (!n) sum.replaceChildren('Seleccione una o más habitaciones vacantes.');
      else if (!(k >= 1)) sum.replaceChildren(h('span', { class: 'vbad' }, 'Revise las fechas: el término debe ser posterior al inicio.'));
      else sum.replaceChildren(h('div', {}, `Por persona: ${k} noche${k > 1 ? 's' : ''} × ${money(COST)} = ${money(k * COST)}`),
        h('div', {}, `Total: ${n} pasajero${n > 1 ? 's' : ''} × ${k} noche${k > 1 ? 's' : ''} × ${money(COST)} = `, h('b', {}, money(n * k * COST))),
        h('div', { class: 'hint' }, 'La fecha y hora de registro se guardan automáticamente al confirmar.'));
    };
    picks.forEach((p) => p.cb.addEventListener('change', sync)); start.addEventListener('change', sync); end.addEventListener('change', sync); sync();
    const send = async () => {
      try {
        const res = await api('POST', '/api/assignments', {
          room_ids: picks.filter((p) => p.cb.checked).map((p) => p.r.id), start_date: start.value, end_date: end.value,
          passengers: people.map((p) => ({ name: p.name.value, rut: p.rut.value, is_responsible: p.resp.checked })) });
        clearDrafts('ci.');
        note(msg, `Check-in #${res.id} registrado en habitación(es) ${res.rooms.join(', ')} del ${day(res.start_date)} al ${day(res.end_date)} (${res.nights} noche${res.nights > 1 ? 's' : ''}). Total a cobrar: ${money(res.total_cost)}`, 'ok');
        setTimeout(() => { tab = 'dashboard'; render(); }, 2200);
      } catch (e) { note(msg, e.message); } // ante un error no se borra nada de lo escrito
    };
    body.replaceChildren(h('section', {}, h('h2', {}, 'Asignación de pasajeros / Check-in'),
      free.length ? h('p', { class: 'hint' }, 'Elija una habitación vacante. Solo puede elegir varias si el grupo excede la mayor habitación libre.') : h('p', {}, 'No hay habitaciones vacantes.'),
      picks.map((p) => h('label', { class: 'pick' }, p.cb, ` N°${p.r.number} · capacidad ${p.r.capacity} · ${cap(p.r.orientation)}`)),
      h('div', { class: 'dates' }, h('label', {}, 'Fecha de inicio ', start), h('label', {}, 'Fecha de término ', end)),
      rowsBox, sum, h('button', { onclick: send }, 'Confirmar check-in'), msg));
  },

  // RF05: registro de Encargados, con correo de la empresa; restablecimiento de contraseña
  async users(body) {
    const list = await api('GET', '/api/users'), msg = h('div'), box = h('div');
    const u = h('input', { placeholder: 'Usuario (3 a 30: letras, números . _ -)', 'aria-label': 'Usuario nuevo' });
    const em = h('input', { type: 'email', placeholder: cfg.email_domain ? `Correo @${cfg.email_domain}` : 'Correo de la empresa', autocomplete: 'off', 'aria-label': 'Correo de la empresa' });
    const p = h('input', { type: 'password', placeholder: 'Contraseña temporal', autocomplete: 'new-password', 'aria-label': 'Contraseña temporal' });
    keep('user.name', u); keep('user.email', em);
    const create = async () => { try { await api('POST', '/api/users', { username: u.value, email: em.value.trim(), password: p.value }); clearDrafts('user.'); render(); } catch (e) { note(msg, e.message); } };
    const reset = (r) => { // formulario para fijar una clave temporal nueva
      const m3 = h('div'), np = h('input', { type: 'password', placeholder: 'Nueva contraseña temporal', autocomplete: 'new-password', 'aria-label': 'Nueva contraseña temporal' });
      const ok = async () => { try { await api('POST', `/api/users/${r.id}/reset-password`, { password: np.value }); note(m3, `Clave de ${r.username} restablecida. Deberá cambiarla al ingresar.`, 'ok'); np.value = ''; } catch (e) { note(m3, e.message); } };
      box.replaceChildren(h('section', {}, h('h2', {}, `Restablecer contraseña de ${r.username}`), np, pwRules(np), h('button', { onclick: ok }, 'Confirmar'),
        h('button', { class: 'sec', onclick: () => box.replaceChildren() }, 'Cancelar'), m3));
    };
    body.replaceChildren(
      h('section', {}, h('h2', {}, 'Registrar personal'),
        h('p', { class: 'hint' }, 'Todo usuario nuevo recibe el perfil único de Encargado de Hotel y debe cambiar su contraseña temporal en el primer ingreso.'),
        u, em, p, pwRules(p), h('button', { onclick: create }, 'Crear Encargado'), msg), box,
      h('section', {}, h('h2', {}, 'Usuarios del sistema'),
        table([['Usuario', (r) => r.username], ['Correo', (r) => r.email ?? '—'], ['Perfil', (r) => h('span', { class: 'badge role-' + r.role }, ROLE[r.role])],
          ['Creado', (r) => when(r.created_at)], ['', (r) => (r.role === 'encargado' ? h('button', { class: 'sec', onclick: () => reset(r) }, 'Restablecer clave') : '')]], list)));
  },

  // Cambio de contraseña propio (también obligatorio con clave temporal)
  async password(body) {
    const msg = h('div'), forced = session.must_change;
    const cur = h('input', { type: 'password', placeholder: 'Contraseña actual', autocomplete: 'current-password', 'aria-label': 'Contraseña actual' });
    const nw = h('input', { type: 'password', placeholder: 'Contraseña nueva', autocomplete: 'new-password', 'aria-label': 'Contraseña nueva' });
    const rp = h('input', { type: 'password', placeholder: 'Repita la contraseña nueva', autocomplete: 'new-password', 'aria-label': 'Repetir contraseña nueva' });
    const save = async () => {
      if (nw.value !== rp.value) return note(msg, 'Las contraseñas nuevas no coinciden');
      try {
        await api('POST', '/api/password', { current_password: cur.value, new_password: nw.value });
        note(msg, 'Contraseña actualizada. Las demás sesiones abiertas se cerraron.', 'ok');
        if (forced) { session.must_change = false; tab = session.role === 'admin' ? 'users' : 'dashboard'; setTimeout(render, 1200); }
        else [cur, nw, rp].forEach((i) => { i.value = ''; });
      } catch (e) { note(msg, e.status === 429 ? '🔒 ' + e.message : e.message, e.status === 429 ? 'lock' : 'err'); }
    };
    body.replaceChildren(h('section', {}, h('h2', {}, 'Cambiar contraseña'),
      forced ? h('div', { class: 'msg lock' }, 'Por seguridad debe cambiar su contraseña temporal antes de continuar.') : '',
      cur, nw, pwRules(nw), rp, h('button', { onclick: save }, 'Guardar contraseña'), msg));
  },

  // Auditoría (ISO/IEC 27002): se actualiza sola cada 10 segundos
  async audit(body) {
    const out = h('div'), stamp = h('span', { class: 'hint' }), auto = h('input', { type: 'checkbox' }); auto.checked = true;
    const act = h('select', { 'aria-label': 'Filtrar por acción' }, h('option', { value: '' }, 'Todas las acciones'),
      Object.entries(ACTIONS).map(([k, t]) => { const o = h('option', { value: k }, t); if (k === audit.action) o.selected = true; return o; }));
    const usr = h('input', { placeholder: 'Filtrar por usuario', value: audit.username, 'aria-label': 'Filtrar por usuario' });
    const load = async () => {
      const q = new URLSearchParams({ page: audit.page, limit: 15 });
      if (audit.action) q.set('action', audit.action); if (audit.username) q.set('username', audit.username);
      const res = await api('GET', '/api/audit?' + q);
      if (!res.rows.length && res.page > 1) { audit.page = res.pages; return load(); }
      const go = (n) => { audit.page = n; load().catch((e) => note(out, e.message)); };
      const prev = h('button', { class: 'sec', disabled: res.page <= 1, onclick: () => go(res.page - 1) }, '← Anterior');
      const next = h('button', { class: 'sec', disabled: res.page >= res.pages, onclick: () => go(res.page + 1) }, 'Siguiente →');
      out.replaceChildren(res.rows.length ? table([['Fecha y hora', (r) => when(r.timestamp)], ['Usuario', (r) => r.username ?? '—'], ['Acción', (r) => ACTIONS[r.action] ?? r.action],
        ['Detalle', (r) => r.details], ['IP', (r) => r.ip_address]], res.rows) : h('p', {}, 'No hay registros para el filtro elegido.'),
        h('div', { class: 'pager' }, prev, `Página ${res.page} de ${res.pages} (${res.total} registros)`, next));
      stamp.textContent = 'Última actualización: ' + new Date().toLocaleTimeString('es-CL');
    };
    const filter = () => { audit.action = act.value; audit.username = usr.value.trim(); audit.page = 1; load().catch((e) => note(out, e.message)); };
    usr.addEventListener('keydown', (e) => e.key === 'Enter' && filter());
    body.replaceChildren(h('section', {}, h('h2', {}, 'Bitácora de auditoría'), act, usr, h('button', { onclick: filter }, 'Filtrar'),
      h('button', { class: 'sec', onclick: () => load().catch((e) => note(out, e.message)) }, 'Actualizar ahora'),
      h('label', { class: 'hint' }, auto, ' Actualizar cada 10 s '), stamp, out));
    await load();
    timer = setInterval(() => { if (auto.checked && session && tab === 'audit' && document.visibilityState === 'visible') load().catch(() => {}); }, 10000);
  },
};

(async () => { try { cfg = await api('GET', '/api/config'); } catch { /* usa valores por defecto */ }
  try { session = await api('GET', '/api/me'); tab = session.role === 'admin' ? 'users' : 'dashboard'; render(); } catch { loginView(); } })();
