// Capa de negocio: reglas del caso Hotel "Duerme Bien"
import { HttpError, normalizeRut, validName } from './security.js';

export const COST_PER_PASSENGER = 40000;

export function listRooms(db) {
  return db.prepare(`
    SELECT r.id, r.number, r.capacity, r.orientation,
      (SELECT COUNT(*) FROM passengers p JOIN assignments a ON a.id = p.assignment_id
        WHERE p.room_id = r.id AND a.checked_out_at IS NULL) AS guests
    FROM rooms r WHERE r.deleted = 0 ORDER BY r.number`).all()
    .map((r) => ({ ...r, status: r.guests > 0 ? 'ocupada' : 'vacante' }));
}

export function createRoom(db, { number, capacity, orientation } = {}) {
  if (!Number.isInteger(number) || number < 1 || number > 9999) throw new HttpError(400, 'Número de habitación inválido');
  if (!Number.isInteger(capacity) || capacity < 1 || capacity > 10) throw new HttpError(400, 'Capacidad debe ser entre 1 y 10');
  if (!['norte', 'sur', 'este', 'oeste'].includes(orientation)) throw new HttpError(400, 'Orientación inválida');
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

export function assign(db, userId, { room_ids, passengers, responsible_index } = {}) {
  if (!Array.isArray(room_ids) || !room_ids.length || room_ids.length > 5 || !room_ids.every(Number.isInteger) || new Set(room_ids).size !== room_ids.length)
    throw new HttpError(400, 'Habitaciones inválidas');
  if (!Array.isArray(passengers) || !passengers.length || passengers.length > 50) throw new HttpError(400, 'Lista de pasajeros inválida');
  if (!Number.isInteger(responsible_index) || responsible_index < 0 || responsible_index >= passengers.length)
    throw new HttpError(400, 'Debe indicar un pasajero responsable (RF14)');

  const people = passengers.map((p) => {
    const rut = normalizeRut(p?.rut);
    if (!validName(p?.full_name) || !rut) throw new HttpError(400, 'Nombre o RUT inválido');
    return { name: p.full_name.trim(), rut };
  });
  if (new Set(people.map((p) => p.rut)).size !== people.length) throw new HttpError(400, 'RUT repetido en la solicitud');
  const hosted = db.prepare(`SELECT 1 FROM passengers p JOIN assignments a ON a.id=p.assignment_id
    WHERE a.checked_out_at IS NULL AND p.rut=?`);
  if (people.some((p) => hosted.get(p.rut))) throw new HttpError(409, 'Un pasajero ya se encuentra hospedado');

  const free = listRooms(db).filter((r) => r.guests === 0);
  const rooms = room_ids.map((id) => free.find((r) => r.id === id));
  if (rooms.some((r) => !r)) throw new HttpError(409, 'Alguna habitación no existe o está ocupada');
  const totalCap = rooms.reduce((s, r) => s + r.capacity, 0);
  if (people.length !== totalCap) throw new HttpError(422, `La cantidad de pasajeros (${people.length}) debe coincidir exactamente con la capacidad (${totalCap}) (RF10)`);
  if (rooms.length > 1 && people.length <= Math.max(...free.map((r) => r.capacity)))
    throw new HttpError(422, 'Solo se pueden reservar varias habitaciones si el grupo excede la habitación más grande disponible (RF13)');

  const total = people.length * COST_PER_PASSENGER; // RF11
  db.exec('BEGIN');
  try {
    const a = db.prepare('INSERT INTO assignments (total_cost,created_at,user_id) VALUES (?,?,?)')
      .run(total, new Date().toISOString(), userId); // RF12
    const aid = Number(a.lastInsertRowid);
    const ins = db.prepare('INSERT INTO passengers (assignment_id,room_id,full_name,rut,is_responsible) VALUES (?,?,?,?,?)');
    let i = 0;
    for (const room of rooms) for (let k = 0; k < room.capacity; k++, i++)
      ins.run(aid, room.id, people[i].name, people[i].rut, i === responsible_index ? 1 : 0);
    db.exec('COMMIT');
    return { id: aid, total_cost: total, passengers: people.length, rooms: rooms.map((r) => r.number) };
  } catch (e) { db.exec('ROLLBACK'); throw e; }
}

export function checkout(db, id) {
  const r = db.prepare('UPDATE assignments SET checked_out_at=? WHERE id=? AND checked_out_at IS NULL')
    .run(new Date().toISOString(), id);
  if (!r.changes) throw new HttpError(404, 'Asignación activa no encontrada');
}

export const listGuests = (db) => db.prepare(`
  SELECT p.full_name, p.rut, r.number AS room, p.is_responsible AS responsible,
         a.id AS assignment_id, a.total_cost, a.created_at
  FROM passengers p JOIN assignments a ON a.id=p.assignment_id JOIN rooms r ON r.id=p.room_id
  WHERE a.checked_out_at IS NULL ORDER BY r.number`).all();
