// Cliente: usa textContent (nunca innerHTML) para evitar XSS (OWASP A03)
let session = null, tab = 'rooms';
const $ = (id) => document.getElementById(id);
const app = $('app');

function h(tag, props = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) k.startsWith('on') ? e.addEventListener(k.slice(2), v) : k === 'class' ? (e.className = v) : e.setAttribute(k, v);
  for (const c of kids.flat()) e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return e;
}

async function api(method, url, body) {
  const r = await fetch(url, {
    method, credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', ...(session ? { 'X-CSRF-Token': session.csrf } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await r.json();
  if (!r.ok) throw new Error(data.error || 'Error');
  return data;
}
const note = (el, text, ok) => { el.replaceChildren(h('div', { class: 'msg ' + (ok ? 'okm' : 'err') }, text)); };
const table = (cols, rows) => h('table', {}, h('tr', {}, cols.map(([t]) => h('th', {}, t))),
  rows.map((r) => h('tr', {}, cols.map(([, f]) => h('td', {}, f(r))))));
const money = (n) => '$' + n.toLocaleString('es-CL');

function loginView() {
  $('who').replaceChildren();
  const msg = h('div');
  const u = h('input', { placeholder: 'Usuario', autocomplete: 'username' });
  const p = h('input', { type: 'password', placeholder: 'Contraseña', autocomplete: 'current-password' });
  const go = async () => {
    try { session = await api('POST', '/api/login', { username: u.value, password: p.value }); tab = session.role === 'admin' ? 'users' : 'rooms'; render(); }
    catch (e) { note(msg, e.message); }
  };
  p.addEventListener('keydown', (e) => e.key === 'Enter' && go());
  app.replaceChildren(h('section', { class: 'login' }, h('h2', {}, 'Iniciar sesión'), u, p, h('button', { onclick: go }, 'Ingresar'), msg));
}

async function render() {
  $('who').replaceChildren(`${session.username} (${session.role}) `, h('button', { class: 'sec', onclick: async () => { await api('POST', '/api/logout'); session = null; loginView(); } }, 'Salir'));
  const tabs = session.role === 'admin'
    ? [['users', 'Usuarios'], ['rooms', 'Habitaciones'], ['guests', 'Pasajeros'], ['audit', 'Auditoría']]
    : [['rooms', 'Habitaciones'], ['assign', 'Asignar'], ['guests', 'Pasajeros']];
  const body = h('div');
  app.replaceChildren(h('nav', {}, tabs.map(([k, t]) => h('button', { class: k === tab ? 'on' : '', onclick: () => { tab = k; render(); } }, t))), body);
  try { await views[tab](body); } catch (e) { note(body, e.message); }
}

const views = {
  async rooms(body) {
    const rooms = await api('GET', '/api/rooms'), msg = h('div');
    const reload = () => render();
    const num = h('input', { type: 'number', placeholder: 'N° hab.', min: 1 }), cap = h('input', { type: 'number', placeholder: 'Capacidad', min: 1, max: 10 });
    const ori = h('select', {}, ['norte', 'sur', 'este', 'oeste'].map((o) => h('option', {}, o)));
    const form = session.role === 'encargado' ? h('section', {}, h('h2', {}, 'Registrar habitación'), num, cap, ori,
      h('button', { onclick: async () => { try { await api('POST', '/api/rooms', { number: +num.value, capacity: +cap.value, orientation: ori.value }); reload(); } catch (e) { note(msg, e.message); } } }, 'Agregar'), msg) : '';
    const cols = [['N°', (r) => r.number], ['Capacidad', (r) => r.capacity], ['Orientación', (r) => r.orientation],
      ['Estado', (r) => h('span', { class: r.status }, r.status)], ['Huéspedes', (r) => r.guests]];
    if (session.role === 'encargado') cols.push(['', (r) => h('button', { class: 'del', onclick: async () => { try { await api('DELETE', '/api/rooms/' + r.id); reload(); } catch (e) { note(msg, e.message); } } }, 'Eliminar')]);
    body.replaceChildren(form, h('section', {}, h('h2', {}, 'Estado de habitaciones'), table(cols, rooms)));
  },
  async assign(body) {
    const free = (await api('GET', '/api/rooms')).filter((r) => r.status === 'vacante'), msg = h('div');
    const picks = free.map((r) => ({ r, cb: h('input', { type: 'checkbox' }) }));
    const rows = h('div'), info = h('div');
    const people = [];
    const addRow = () => {
      const name = h('input', { placeholder: 'Nombre completo' }), rut = h('input', { placeholder: 'RUT 12345678-5' }), resp = h('input', { type: 'radio', name: 'resp' });
      people.push({ name, rut, resp }); rows.append(h('div', {}, resp, ' responsable ', name, rut));
      if (people.length === 1) resp.checked = true;
    };
    addRow();
    const upd = () => { const cap = picks.filter((p) => p.cb.checked).reduce((s, p) => s + p.r.capacity, 0); info.textContent = `Capacidad seleccionada: ${cap} · Pasajeros: ${people.length} · Costo: ${money(people.length * 40000)}`; };
    picks.forEach((p) => p.cb.addEventListener('change', upd)); upd();
    const send = async () => {
      try {
        const res = await api('POST', '/api/assignments', {
          room_ids: picks.filter((p) => p.cb.checked).map((p) => p.r.id),
          passengers: people.map((p) => ({ full_name: p.name.value, rut: p.rut.value })),
          responsible_index: people.findIndex((p) => p.resp.checked) });
        note(msg, `Asignación #${res.id} creada. Total: ${money(res.total_cost)}`, true);
      } catch (e) { note(msg, e.message); }
    };
    body.replaceChildren(h('section', {}, h('h2', {}, 'Registrar pasajeros y asignar habitación'),
      h('p', {}, 'Habitaciones vacantes:'), picks.map((p) => h('label', {}, p.cb, ` N°${p.r.number} (cap. ${p.r.capacity}, ${p.r.orientation}) `)),
      rows, h('button', { class: 'sec', onclick: () => { addRow(); upd(); } }, '+ Pasajero'), h('button', { onclick: send }, 'Asignar'), info, msg));
  },
  async guests(body) {
    const g = await api('GET', '/api/passengers'), msg = h('div');
    const cols = [['Hab.', (r) => r.room], ['Pasajero', (r) => r.full_name], ['RUT', (r) => r.rut], ['Responsable', (r) => (r.responsible ? 'Sí' : '')],
      ['Ingreso', (r) => new Date(r.created_at).toLocaleString('es-CL')], ['Costo asignación', (r) => money(r.total_cost)]];
    if (session.role === 'encargado') cols.push(['', (r) => (r.responsible ? h('button', { class: 'sec', onclick: async () => { await api('POST', `/api/assignments/${r.assignment_id}/checkout`); render(); } }, 'Check-out') : '')]);
    body.replaceChildren(h('section', {}, h('h2', {}, 'Pasajeros hospedados'), table(cols, g), msg));
  },
  async users(body) {
    const list = await api('GET', '/api/users'), msg = h('div');
    const u = h('input', { placeholder: 'Usuario' }), p = h('input', { type: 'password', placeholder: 'Contraseña (10+ con números)' });
    body.replaceChildren(h('section', {}, h('h2', {}, 'Registrar Encargado de Hotel'), u, p,
      h('button', { onclick: async () => { try { await api('POST', '/api/users', { username: u.value, password: p.value }); render(); } catch (e) { note(msg, e.message); } } }, 'Crear'), msg),
      h('section', {}, h('h2', {}, 'Usuarios'), table([['Usuario', (r) => r.username], ['Rol', (r) => r.role]], list)));
  },
  async audit(body) {
    const a = await api('GET', '/api/audit');
    body.replaceChildren(h('section', {}, h('h2', {}, 'Registro de accesos y acciones (últimos 100)'),
      table([['Fecha', (r) => r.ts], ['Usuario', (r) => r.username], ['Acción', (r) => r.action], ['Detalle', (r) => r.detail], ['IP', (r) => r.ip]], a)));
  },
};

(async () => { try { session = await api('GET', '/api/me'); render(); } catch { loginView(); } })();
