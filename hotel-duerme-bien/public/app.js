// Cliente SPA. Datos dinámicos solo con createElement/textContent (nunca innerHTML) - OWASP A03
const ORIENTATIONS = ['norte', 'sur', 'este', 'oeste', 'vista interior', 'vista exterior'];
const ACTIONS = ['login', 'logout', 'create_user', 'create_room', 'delete_room', 'assign_passengers', 'checkout'];
const COST = 40000;
let session = null, tab = 'rooms';
const audit = { page: 1, action: '', username: '' };
const $ = (id) => document.getElementById(id);
const app = $('app');

function h(tag, props = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'class') e.className = v;
    else e.setAttribute(k, v);
  }
  for (const c of kids.flat()) if (c !== null && c !== undefined && c !== false) e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return e;
}
async function api(method, url, body) {
  const r = await fetch(url, {
    method, credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', ...(session ? { 'X-CSRF-Token': session.csrf } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await r.json();
  if (r.status === 401 && session) { session = null; loginView(); throw new Error('Sesión expirada'); }
  if (!r.ok) throw new Error(data.error || 'Error');
  return data;
}
const note = (el, text, ok) => el.replaceChildren(h('div', { class: 'msg ' + (ok ? 'okm' : 'err'), role: 'alert' }, text));
const table = (cols, rows) => h('div', { class: 'tw' }, h('table', {}, h('thead', {}, h('tr', {}, cols.map(([t]) => h('th', {}, t)))),
  h('tbody', {}, rows.map((r) => h('tr', {}, cols.map(([, f]) => h('td', {}, f(r))))))));
const badge = (status) => h('span', { class: 'badge ' + status }, status === 'vacante' ? 'Vacante' : 'Ocupada');
const money = (n) => '$' + n.toLocaleString('es-CL');
const when = (iso) => new Date(iso).toLocaleString('es-CL');

function loginView() {
  $('who').replaceChildren();
  const msg = h('div');
  const u = h('input', { placeholder: 'Usuario', autocomplete: 'username', 'aria-label': 'Usuario' });
  const p = h('input', { type: 'password', placeholder: 'Contraseña', autocomplete: 'current-password', 'aria-label': 'Contraseña' });
  const go = async () => {
    try { session = await api('POST', '/api/login', { username: u.value, password: p.value }); tab = session.role === 'admin' ? 'users' : 'rooms'; render(); }
    catch (e) { note(msg, e.message); }
  };
  p.addEventListener('keydown', (e) => e.key === 'Enter' && go());
  app.replaceChildren(h('section', { class: 'login' }, h('h2', {}, 'Iniciar sesión'), u, p, h('button', { onclick: go }, 'Ingresar'), msg));
}

async function render() {
  $('who').replaceChildren(`${session.username} (${session.role}) `,
    h('button', { class: 'sec', onclick: async () => { try { await api('POST', '/api/logout'); } finally { session = null; loginView(); } } }, 'Salir'));
  const tabs = session.role === 'admin'
    ? [['users', 'Usuarios'], ['audit', 'Auditoría'], ['rooms', 'Habitaciones'], ['guests', 'Pasajeros']]
    : [['rooms', 'Habitaciones'], ['assign', 'Check-in'], ['guests', 'Pasajeros hospedados']];
  const body = h('div');
  app.replaceChildren(h('nav', {}, tabs.map(([k, t]) => h('button', { class: k === tab ? 'on' : '', onclick: () => { tab = k; render(); } }, t))), body);
  try { await views[tab](body); } catch (e) { if (session) note(body, e.message); }
}

const views = {
  async rooms(body) {
    const rooms = await api('GET', '/api/rooms'), msg = h('div'), enc = session.role === 'encargado';
    const num = h('input', { type: 'number', placeholder: 'N° hab.', min: 1, max: 9999, 'aria-label': 'Número' });
    const cap = h('input', { type: 'number', placeholder: 'Capacidad (1-10)', min: 1, max: 10, 'aria-label': 'Capacidad' });
    const ori = h('select', { 'aria-label': 'Orientación' }, ORIENTATIONS.map((o) => h('option', {}, o)));
    const form = enc ? h('section', {}, h('h2', {}, 'Registrar habitación'), num, cap, ori,
      h('button', { onclick: async () => { try { await api('POST', '/api/rooms', { number: +num.value, capacity: +cap.value, orientation: ori.value }); render(); } catch (e) { note(msg, e.message); } } }, 'Agregar'), msg) : '';
    const cards = rooms.map((r) => h('div', { class: 'room ' + r.status },
      h('h3', {}, 'Habitación ' + r.number), badge(r.status),
      h('p', {}, `Capacidad: ${r.capacity}`), h('p', {}, `Orientación: ${r.orientation}`), h('p', {}, `Huéspedes: ${r.guests}`),
      enc ? h('button', { class: 'del', onclick: async () => { try { await api('DELETE', '/api/rooms/' + r.id); render(); } catch (e) { note(msg2, e.message); } } }, 'Eliminar') : ''));
    const msg2 = h('div');
    body.replaceChildren(form, h('section', {}, h('h2', {}, 'Estado de habitaciones'), msg2,
      cards.length ? h('div', { class: 'grid' }, cards) : h('p', {}, 'No hay habitaciones registradas.')));
  },

  async assign(body) {
    const free = (await api('GET', '/api/rooms')).filter((r) => r.status === 'vacante'), msg = h('div');
    const picks = free.map((r) => ({ r, cb: h('input', { type: 'checkbox' }) }));
    const rowsBox = h('div'), info = h('div', { class: 'msg okm' });
    const people = []; // { name, rut, resp, el }
    const need = () => picks.filter((p) => p.cb.checked).reduce((s, p) => s + p.r.capacity, 0);
    const addRow = () => {
      const n = people.length + 1;
      const name = h('input', { type: 'text', placeholder: `Pasajero ${n}: nombre completo`, 'aria-label': `Nombre pasajero ${n}` });
      const rut = h('input', { type: 'text', placeholder: 'RUT 12345678-5', 'aria-label': `RUT pasajero ${n}` });
      const resp = h('input', { type: 'radio', name: 'resp', 'aria-label': `Responsable: pasajero ${n}` });
      const el = h('div', { class: 'prow' }, h('label', {}, resp, ' Responsable'), name, rut);
      people.push({ name, rut, resp, el }); rowsBox.append(el);
    };
    const sync = () => { // un formulario por pasajero, según la capacidad seleccionada
      const n = need();
      while (people.length < n) addRow();
      while (people.length > n) people.pop().el.remove();
      if (people.length && !people.some((p) => p.resp.checked)) people[0].resp.checked = true;
      info.textContent = n ? `Capacidad seleccionada: ${n} · Pasajeros a ingresar: ${n} · Costo total: ${money(n * COST)} (${money(COST)} × ${n})`
        : 'Seleccione una o más habitaciones vacantes.';
    };
    picks.forEach((p) => p.cb.addEventListener('change', sync));
    sync();
    const send = async () => {
      try {
        const res = await api('POST', '/api/assignments', {
          room_ids: picks.filter((p) => p.cb.checked).map((p) => p.r.id),
          passengers: people.map((p) => ({ name: p.name.value, rut: p.rut.value, is_responsible: p.resp.checked })) });
        note(msg, `Check-in #${res.id} registrado. Total: ${money(res.total_cost)}`, true);
        setTimeout(render, 1500);
      } catch (e) { note(msg, e.message); }
    };
    body.replaceChildren(h('section', {}, h('h2', {}, 'Formulario de asignación / Check-in'),
      free.length ? h('p', {}, 'Habitaciones disponibles (si el grupo excede la mayor habitación libre puede elegir varias):') : h('p', {}, 'No hay habitaciones vacantes.'),
      picks.map((p) => h('label', { class: 'pick' }, p.cb, ` N°${p.r.number} · capacidad ${p.r.capacity} · ${p.r.orientation}`)),
      rowsBox, info, h('button', { onclick: send }, 'Registrar check-in'), msg));
  },

  async guests(body) {
    const g = await api('GET', '/api/passengers'), msg = h('div');
    const cols = [['Hab.', (r) => r.room], ['Pasajero', (r) => r.name], ['RUT', (r) => r.rut], ['Responsable', (r) => (r.responsible ? 'Sí' : '')],
      ['Ingreso', (r) => when(r.created_at)], ['Costo grupo', (r) => money(r.total_cost)]];
    if (session.role === 'encargado') cols.push(['', (r) => (r.responsible ? h('button', { class: 'sec', onclick: async () => {
      try { await api('POST', `/api/assignments/${r.assignment_id}/checkout`); render(); } catch (e) { note(msg, e.message); } } }, 'Check-out') : '')]);
    body.replaceChildren(h('section', {}, h('h2', {}, 'Pasajeros hospedados'), g.length ? table(cols, g) : h('p', {}, 'No hay pasajeros hospedados.'), msg));
  },

  async users(body) {
    const list = await api('GET', '/api/users'), msg = h('div');
    const u = h('input', { placeholder: 'Usuario (3-30, letras/números . _ -)', 'aria-label': 'Usuario nuevo' });
    const p = h('input', { type: 'password', placeholder: 'Contraseña (10+ con letras y números)', 'aria-label': 'Contraseña nueva' });
    body.replaceChildren(h('section', {}, h('h2', {}, 'Registrar Encargado de Hotel'), u, p,
      h('button', { onclick: async () => {
        if (p.value.length < 10 || !/[A-Za-z]/.test(p.value) || !/\d/.test(p.value)) return note(msg, 'La contraseña debe tener mínimo 10 caracteres con letras y números');
        try { await api('POST', '/api/users', { username: u.value, password: p.value }); render(); } catch (e) { note(msg, e.message); } } }, 'Crear'), msg),
      h('section', {}, h('h2', {}, 'Usuarios'), table([['Usuario', (r) => r.username], ['Rol', (r) => r.role], ['Creado', (r) => when(r.created_at)]], list)));
  },

  async audit(body) {
    const q = new URLSearchParams({ page: audit.page, limit: 15 });
    if (audit.action) q.set('action', audit.action);
    if (audit.username) q.set('username', audit.username);
    const res = await api('GET', '/api/audit?' + q);
    const act = h('select', { 'aria-label': 'Filtrar por acción' }, h('option', { value: '' }, 'Todas las acciones'),
      ACTIONS.map((a) => { const o = h('option', { value: a }, a); if (a === audit.action) o.selected = true; return o; }));
    const usr = h('input', { placeholder: 'Filtrar por usuario', value: audit.username, 'aria-label': 'Filtrar por usuario' });
    const go = (page) => { audit.page = page; render(); };
    const filter = () => { audit.action = act.value; audit.username = usr.value.trim(); go(1); };
    usr.addEventListener('keydown', (e) => e.key === 'Enter' && filter());
    const prev = h('button', { class: 'sec', onclick: () => go(res.page - 1) }, '← Anterior'), next = h('button', { class: 'sec', onclick: () => go(res.page + 1) }, 'Siguiente →');
    if (res.page <= 1) prev.disabled = true; if (res.page >= res.pages) next.disabled = true;
    body.replaceChildren(h('section', {}, h('h2', {}, 'Bitácora de auditoría'), act, usr, h('button', { onclick: filter }, 'Filtrar'),
      table([['Fecha y hora', (r) => when(r.timestamp)], ['Usuario', (r) => r.username ?? '—'], ['Acción', (r) => r.action], ['Detalle', (r) => r.details], ['IP', (r) => r.ip_address]], res.rows),
      h('div', { class: 'pager' }, prev, `Página ${res.page} de ${res.pages} (${res.total} registros)`, next)));
  },
};

(async () => { try { session = await api('GET', '/api/me'); render(); } catch { loginView(); } })();
