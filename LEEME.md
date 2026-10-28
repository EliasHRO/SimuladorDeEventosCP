# Simulador de escenario en Cloudflare Workers

Publica el simulador con usuarios propios (nombre, correo y contraseña), aprobación del Owner y permisos guardados en Cloudflare D1.

## Contenido

| Archivo | Para qué sirve |
|---|---|
| `public/index.html` | El simulador con inicio de sesión y registro |
| `public/admin.html` | Panel de administración (solo el Owner) |
| `src/index.js` | Entrada del Worker: `/api/*` va al servidor y el resto a `public` |
| `src/api.js` | Registro, inicio de sesión, sesiones y permisos |
| `schema.sql` | Tablas de la base de datos |
| `wrangler.toml` | Configuración del Worker |

## Publicar con GitHub

1. En Cloudflare D1, crea la base `simulador-db`, ejecuta `schema.sql` en su **Console** y copia su **Database ID**.
2. En `wrangler.toml`, reemplaza `PEGA_AQUI_EL_ID_DE_TU_BASE_D1` por ese ID. El valor de `name` debe ser igual al nombre del Worker en Cloudflare.
3. Sube el proyecto a un repositorio privado de GitHub.
4. En Cloudflare: **Workers & Pages → Create → Continue with GitHub**, elige el repositorio, deja **Build command** vacío y **Deploy command** en `npx wrangler deploy`, y pulsa **Deploy**.
5. En el Worker: **Settings → Variables and Secrets → Add**, tipo **Secret**, nombre `SETUP_KEY`, con una clave larga que solo tú conozcas.
6. Abre la dirección `.workers.dev`, completa **Configuración inicial** con la clave `SETUP_KEY` y crea tu cuenta de Owner.

Cada cambio que subas a la rama `main` se publica solo.

## Seguridad

- Contraseñas cifradas con PBKDF2 y sal; nadie puede leerlas.
- Sesiones de 7 días que se cierran al suspender o eliminar al usuario.
- 5 intentos fallidos bloquean ese correo 15 minutos.
- Registro, aprobación, suspensión y permisos se validan en el servidor; los límites de luces, escenas y controles se aplican en el navegador.
- Sin recuperación por correo: el Owner restablece contraseñas desde el panel.

## Respaldo de usuarios

`npx wrangler d1 export simulador-db --remote --output respaldo.sql`
