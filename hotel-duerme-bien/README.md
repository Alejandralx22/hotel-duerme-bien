# Hotel “Duerme Bien” — Prototipo funcional (Ingeniería de Software, Unidad 3)

Sistema web para gestionar habitaciones, pasajeros y asignaciones, con roles **Administrador** y **Encargado de Hotel**.
Implementa los requerimientos RF01–RF16 del informe de la Unidad 2.

## Contraseñas y verificación por correo
- **Cambiar contraseña:** pestaña "Cambiar contraseña" (ambos roles). Pide la actual, aplica la política (10+ con letras y números) y cierra las demás sesiones.
- **Clave temporal:** los usuarios creados por el Administrador (o con clave restablecida) deben cambiarla en su primer ingreso; mientras no lo hagan el servidor rechaza todo lo demás (403).
- **Olvidé mi contraseña:** el Administrador la restablece desde la pestaña Usuarios ("Restablecer clave").
- **Código por correo (2FA):** tras la contraseña, el sistema envía un código de 6 dígitos al correo de la empresa del usuario (vence en 10 minutos, un solo uso, 5 intentos, reenvío cada 1 minuto). Los códigos erróneos cuentan para el bloqueo de 15 minutos.
- Variables: `MFA_EMAIL=0` lo desactiva; `COMPANY_EMAIL_DOMAIN` (ej. `duermebien.cl`) obliga a usar correos de la empresa; `ADMIN_EMAIL`; y para enviar correos reales `SMTP_HOST`, `SMTP_PORT` (587 STARTTLS o 465 con `SMTP_SECURE=1`), `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`.
- **Sin `SMTP_HOST` el código se imprime en la consola del servidor** (sirve para la demo, no para producción). El envío SMTP se probó contra un servidor de prueba local; la conexión cifrada (STARTTLS/SMTPS) conviene probarla con su proveedor real antes de producción.
- El esquema de la base de datos cambió (versión 4): borra `data/hotel.db` si tenías una anterior.

## Si el sistema te devuelve al ingreso
- **Producción por http:** una cookie `Secure` no viaja por http y el navegador la descarta; por eso la cookie solo se marca `Secure` cuando la conexión es HTTPS. En producción publique siempre detrás de HTTPS (el sistema muestra un aviso si se abre por http fuera de localhost).
- **Navegador sin cookies:** tras ingresar, el sistema comprueba que la sesión quedó guardada; si no, lo explica en vez de entrar en bucle.
- **Sesión vencida (8 horas) a mitad de una acción:** al volver a ingresar regresa a la misma pestaña y conserva lo escrito.

## Estadía y cobro
- Cada check-in registra **fecha de inicio y de término**; las noches se calculan solas.
- **Total = pasajeros × noches × $40.000.** Pantalla y API muestran el costo por persona (noches × $40.000) y el total del grupo.
- La habitación tiene una **vista**: "al mar" o "a la ciudad".
- Lo escrito en los formularios (usuarios, habitaciones y check-in) se conserva si hay un error o se cambia de pestaña; las contraseñas nunca se guardan.

## Ejecutar (requiere Node.js ≥ 22.5, sin `npm install`)
```bash
npm start            # http://localhost:3000
npm test             # 33 pruebas automatizadas
```
Al primer arranque se crea el usuario `admin` con una **contraseña aleatoria que se imprime en consola** (o la de `ADMIN_PASSWORD`).
Flujo de demo: entrar como `admin` → crear un Encargado → salir → entrar como Encargado → crear habitaciones → asignar pasajeros → check-out.
API de asignación: `POST /api/assignments` con `{ room_ids: [..], passengers: [{ name, rut, is_responsible }] }` (exactamente un responsable).
Variables de entorno: `PORT`, `DB_FILE`, `ADMIN_PASSWORD`, `NODE_ENV=production` (cookie Secure + HSTS cuando la conexión es HTTPS) y `TRUST_PROXY=1` (detrás de un proxy cloud, para registrar y bloquear por la IP real).
Si tenías una base de datos de una versión anterior, borra `data/hotel.db`: el esquema cambió (`checkout_at`, `room_ids`, `audit_log`, etc.) y el sistema avisa si detecta uno antiguo.
RUT de prueba válidos: `11111111-1`, `22222222-2`, `12345678-5`.

## Tecnologías (todas libres) y arquitectura
| Capa | Tecnología | Archivo |
|---|---|---|
| Presentación (cliente) | HTML + JS vanilla + CSS | `public/` |
| API / control de acceso | Node.js (`http`), sesiones, CSRF, cabeceras | `src/app.js` |
| Lógica de negocio | Reglas RF06–RF14 | `src/services.js` |
| Seguridad transversal | scrypt, validaciones, anti fuerza bruta | `src/security.js` |
| Datos | SQLite (`node:sqlite`) | `src/db.js` |

**Arquitectura: cliente-servidor en capas** (presentación → API → negocio → datos), con módulos independientes (RNF05): autenticación, habitaciones, pasajeros y reportes.
Elegida por el tamaño del proyecto (1 hotel, equipo de 3–4): un microservicio por módulo sería sobreingeniería; las capas permiten migrar a servicios después.

**Cloud (PaaS + contenedor):** `Dockerfile` y `render.yaml` permiten desplegarlo como **PaaS** (Render, Railway, Fly.io) con disco persistente y HTTPS gestionado (`NODE_ENV=production` activa cookie `Secure` y HSTS). El cliente accede como **SaaS** vía navegador: el hotel no instala ni mantiene servidores (RNF04, sin equipo de TI propio).

## OWASP Top 10 (edición 2021) aplicado
| Riesgo | Control en el prototipo |
|---|---|
| A01 Control de acceso | Roles verificados en el servidor por ruta; clientes sin acceso (RF04); el Administrador no lee datos de la operación; 401/403 |
| A02 Criptografía | Contraseñas con scrypt + sal; token de sesión aleatorio guardado como SHA-256; cookie `Secure` cuando la conexión es HTTPS (siempre, en producción detrás de un proveedor cloud) |
| A03 Inyección / XSS | Consultas parametrizadas; validación de entradas; el cliente usa `textContent` (nunca `innerHTML`); CSP |
| A04 Diseño inseguro | Reglas de negocio validadas en servidor (capacidad exacta, RUT módulo 11, transacciones) |
| A05 Configuración | CSP, `X-Frame-Options`, `nosniff`, HSTS; errores genéricos; sin credenciales por defecto |
| A07 Autenticación | Bloqueo tras 5 fallos (15 min); mensaje genérico; sesión 8 h con logout que la invalida; CSRF token |
| A09 Registro y monitoreo | Tabla `audit_log` (logins, altas, bajas, asignaciones) visible al Administrador |

## ISO/IEC 27000 y marco legal
- **27001** (gestión): acceso por rol, responsables definidos, perfil único por usuario.
- **27002** (controles): cifrado de contraseñas, registro de accesos, política de contraseñas (10+ con letras y números), respaldo = copiar `data/hotel.db`.
- **Ley 21.459 (delitos informáticos, Chile):** los controles de acceso, bloqueo anti fuerza bruta y trazabilidad previenen y permiten evidenciar acceso ilícito o alteración de datos; se registra quién hizo cada acción.
- **ISO 9001 / 25010:** pruebas documentadas, requerimientos trazables (IDs RF/RNF en código y tests), mantenibilidad por capas.

## Casos de prueba (`tests/api.test.js`) — todos pasan
| ID | Caso | Resultado esperado |
|---|---|---|
| CP-01 | Login válido | 200, cookie HttpOnly + SameSite |
| CP-02 | Clave incorrecta / usuario inexistente | 401, mismo mensaje (no enumera usuarios) |
| CP-03 | Inyección SQL en login | 401 |
| CP-04 | 6 intentos fallidos | 429 |
| CP-05 | Contraseñas en BD | Solo hash scrypt (RNF01) |
| CP-06 | Sin sesión / rol incorrecto | 401 / 403 |
| CP-07 | POST sin token CSRF | 403 |
| CP-08 | Admin crea Encargado; clave débil | 201 / 400 (RF03, RF05) |
| CP-09 | N° de habitación duplicado | 409 (RF06) |
| CP-10 | 1 o 3 pasajeros en hab. de 2 / 2 pasajeros | 422 / 201 (RF10) |
| CP-11 | 3 pasajeros | Costo $120.000, fecha y 1 responsable (RF11, RF12, RF14) |
| CP-12 | RUT inválido o repetido | 400 |
| CP-13 | Eliminar hab. con pasajeros / tras check-out | 409 / 200, historial conservado (RF07, RF08) |
| CP-14 | Varias habitaciones | Rechazo si cabe en una; aceptado si excede la mayor (RF13) |
| CP-15 | Resumen de habitaciones | Estados ocupada/vacante (RF15) |
| CP-16 | Cabeceras de seguridad, JSON malformado | CSP/nosniff presentes; 400 sin fuga |
| CP-17 | Path traversal en estáticos | 404 |
| CP-18 | Mensaje genérico y 5 fallos desde una misma IP | "Credenciales inválidas"; luego 429 aun con clave correcta |
| CP-19 | Bitácora con filtros y paginación | Filtra por acción/usuario, pagina; 400 si el filtro es inválido; 403 para el Encargado |
| CP-20 | Un solo responsable; orientaciones | Rechaza 0 o 2 responsables (RF14); acepta "vista a la ciudad", rechaza valores inválidos |
| CP-21 | Login en dos pasos | Sin cookie hasta validar el código del correo; código de un solo uso |
| CP-22 | 5 códigos erróneos | 429 (bloqueo de 15 minutos) |
| CP-23 | Reenvío y vencimiento | Reenvío con espera de 1 minuto (429); código vencido: 401 |
| CP-24 | Cambio de contraseña | Valida la actual, la política y que sea distinta; cierra las otras sesiones |
| CP-25 | Usuario nuevo | Exige correo de la empresa único; debe cambiar la clave temporal antes de operar |
| CP-26 | Restablecer clave | Solo el Administrador, solo a Encargados; cierra sus sesiones y exige cambio |
| CP-27 | Mailer SMTP | Entrega el correo a un servidor SMTP de prueba; rechaza inyección de cabeceras |
| CP-28 | Mínimo privilegio | El Administrador no lee habitaciones ni pasajeros (403); el Encargado no ve usuarios |
| CP-29 | Sesión | El token deja de servir al cerrar sesión y al vencer |
| CP-30 | Entradas maliciosas | Rechaza HTML/script en nombres, trata % y _ como texto y rechaza cuerpos de más de 10 KB |
| CP-31 | Producción | Con HTTPS (X-Forwarded-Proto): cookie Secure y HSTS. Por http plano la sesión sigue funcionando (sin Secure ni HSTS) |
| CP-32 | Fechas de inicio y término | Total = pasajeros × noches × $40.000 (por persona y por noche); rechaza 0 noches, término anterior, fechas inexistentes, inicio pasado, más de 365 noches y falta de fechas |
| CP-33 | Vista de la habitación | Solo "vista al mar" o "vista a la ciudad" |

## Limitaciones conocidas (prototipo)
Límite de intentos en memoria (con varias instancias usar Redis); sin autoservicio de “olvidé mi contraseña” (la restablece el Administrador); respaldo manual; una sola sede (RNF06 se resuelve agregando tabla `hotels`).
