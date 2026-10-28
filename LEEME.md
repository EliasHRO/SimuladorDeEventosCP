# Simulador de escenario en Cloudflare

Esta carpeta publica el simulador en **Cloudflare Pages** con usuarios propios (nombre, correo y contraseña), aprobación del Owner y permisos por usuario guardados en **Cloudflare D1**.

## Qué contiene

| Archivo | Para qué sirve |
|---|---|
| `public/index.html` | El simulador, con pantalla de inicio de sesión y registro |
| `public/admin.html` | Panel de administración (solo el Owner) |
| `functions/api/[[path]].js` | El servidor: registro, inicio de sesión, sesiones y permisos |
| `schema.sql` | Las tablas de la base de datos |
| `wrangler.toml` | Configuración del proyecto en Cloudflare |

## Requisitos

- Una cuenta de Cloudflare (el plan gratuito alcanza).
- Node.js 18 o superior instalado en tu computadora.

## Pasos para publicarlo (una sola vez)

Abre una terminal dentro de esta carpeta y ejecuta, en orden:

1. Instalar la herramienta de Cloudflare:
   `npm install`
2. Iniciar sesión en Cloudflare (abre el navegador):
   `npx wrangler login`
3. Crear la base de datos:
   `npx wrangler d1 create simulador-db`
   Copia el `database_id` que aparece y pégalo en `wrangler.toml`, en lugar de `PEGA_AQUI_EL_ID_DE_TU_BASE_D1`.
4. Crear las tablas:
   `npx wrangler d1 execute simulador-db --remote --file=schema.sql`
5. Crear el proyecto de Pages:
   `npx wrangler pages project create simulador-escenario --production-branch main`
6. Guardar la clave de configuración inicial (escribe una clave larga y guárdala; solo se usa para crear al Owner):
   `npx wrangler pages secret put SETUP_KEY --project-name simulador-escenario`
7. Publicar:
   `npx wrangler pages deploy`

Al terminar, Cloudflare muestra la dirección, por ejemplo `https://simulador-escenario.pages.dev`.

## Primer ingreso: crear al Owner

1. Abre la dirección del simulador.
2. Como todavía no existe un Owner, aparece **Configuración inicial**.
3. Escribe la clave `SETUP_KEY` del paso 6, tu nombre, tu correo y tu contraseña.
4. Entras como **Owner** y ves el botón **Panel de administración**.

Esta pantalla desaparece para siempre cuando el Owner ya existe.

## Uso diario

- Las personas abren la dirección, pulsan **Regístrate** y llenan nombre, correo y contraseña.
- Tú las apruebas en el **Panel de administración** (`/admin.html`) y defines sus permisos.
- Si alguien olvida su contraseña, usa **Restablecer contraseña** en el panel: se genera una contraseña temporal que le compartes, y el sistema le pide cambiarla al entrar.

## Actualizar el simulador

Reemplaza el archivo en `public/` y vuelve a ejecutar `npx wrangler pages deploy`. Los usuarios y permisos no se pierden.

## Respaldo de usuarios

`npx wrangler d1 export simulador-db --remote --output respaldo.sql`

## Seguridad

- Las contraseñas se guardan cifradas (PBKDF2 con SHA-256 y sal aleatoria); nadie puede leerlas, ni siquiera el Owner.
- Las sesiones duran 7 días y se cierran al suspender o eliminar al usuario.
- Después de 5 intentos fallidos, ese correo queda bloqueado 15 minutos.
- El registro, la aprobación, la suspensión y los permisos se validan en el servidor.
- Los límites dentro del simulador (cantidad de luces, escenas, controles) se aplican en el navegador; sirven para capacitación, no para proteger información sensible.
- No hay recuperación de contraseña por correo: el Owner la restablece desde el panel.

## Probarlo en tu computadora antes de publicar (opcional)

1. Crea un archivo `.dev.vars` con la línea `SETUP_KEY=una-clave-de-prueba`.
2. `npx wrangler d1 execute simulador-db --local --file=schema.sql`
3. `npx wrangler pages dev`
4. Abre `http://localhost:8788`.
