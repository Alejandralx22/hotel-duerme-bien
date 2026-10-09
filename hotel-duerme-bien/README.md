# Hotel “Duerme Bien” — Prototipo funcional (Ingeniería de Software, Unidad 3)

Sistema web para gestionar habitaciones, pasajeros y asignaciones, con roles **Administrador** y **Encargado de Hotel**.
Implementa los requerimientos RF01–RF16 del informe de la Unidad 2.

## Ejecutar (requiere Node.js ≥ 22.5, sin `npm install`)
```bash
npm start            # http://localhost:3000
npm test             # 17 pruebas automatizadas
```
Al primer arranque se crea el usuario `admin` con una **contraseña aleatoria que se imprime en consola** (o la de `ADMIN_PASSWORD`).
Flujo de demo: entrar como `admin` → crear un Encargado → salir → entrar como Encargado → crear habitaciones → asignar pasajeros → check-out.
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
| A01 Control de acceso | Roles verificados en el servidor por ruta; clientes sin acceso (RF04); 401/403 |
| A02 Criptografía | Contraseñas con scrypt + sal; token de sesión aleatorio guardado como SHA-256; cookie `Secure` en producción |
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

## Limitaciones conocidas (prototipo)
Límite de intentos en memoria (con varias instancias usar Redis); sin recuperación de contraseña; respaldo manual; una sola sede (RNF06 se resuelve agregando tabla `hotels`).
