// API del Simulador de escenario (Cloudflare Workers + D1)
// Usuarios con nombre, correo y contraseña; aprobación y permisos por el Owner.

const enc = new TextEncoder();
const SESSION_DAYS = 7;
const PBKDF2_ITER = 100000;
const TYPES = ['par', 'movil', 'wash', 'contra', 'barra', 'strobe', 'blinder', 'confeti'];
const TABS = ['luces', 'pantallas', 'sonido', 'conexiones'];
const CTRLS = ['dim', 'color', 'strobe', 'move', 'presets', 'blackout'];
// Planes por defecto; el Owner los cambia en el panel (nombre, precio, descripción y permisos)
const ALL_TYPES = Object.fromEntries(TYPES.map(k => [k, true]));
const DEFAULT_PLANS = {
  free: {name: 'Gratuito', price: 'Gratis', desc: 'Para conocer el simulador.', perms: {
    tabs: {luces: true, pantallas: true, sonido: true, conexiones: true}, venue: false, patch: true, maxFix: 10, maxPerGroup: 2,
    types: {par: true, movil: true, wash: false, contra: true, barra: false, strobe: false, blinder: false, confeti: false},
    ctrl: {dim: true, color: true, strobe: false, move: true, presets: true, blackout: true}, scenes: true, maxScenes: 3}},
  basico: {name: 'Básico', price: '', desc: 'Para practicar con el equipo de tu iglesia.', perms: {
    tabs: {luces: true, pantallas: true, sonido: true, conexiones: true}, venue: true, patch: true, maxFix: 40, maxPerGroup: 8,
    types: {par: true, movil: true, wash: true, contra: true, barra: true, strobe: true, blinder: false, confeti: false},
    ctrl: {dim: true, color: true, strobe: true, move: true, presets: true, blackout: true}, scenes: true, maxScenes: 15}},
  pro: {name: 'Pro', price: '', desc: 'Todo el simulador, sin límites.', perms: {
    tabs: {luces: true, pantallas: true, sonido: true, conexiones: true}, venue: true, patch: true, maxFix: 96, maxPerGroup: 24,
    types: ALL_TYPES, ctrl: {dim: true, color: true, strobe: true, move: true, presets: true, blackout: true}, scenes: true, maxScenes: 99}}
};
const PLAN_IDS = Object.keys(DEFAULT_PLANS);
const PERM_BASIC = {
  tabs: {luces: true, pantallas: true, sonido: true, conexiones: true}, venue: false, patch: true, maxFix: 24,
  types: {par: true, movil: true, wash: false, contra: true, barra: true, strobe: false, blinder: false, confeti: false},
  ctrl: {dim: true, color: true, strobe: false, move: true, presets: true, blackout: true}, scenes: true, maxScenes: 5
};

// ---------- utilidades ----------
const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), {
  status, headers: Object.assign({'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store'}, headers)
});
const fail = (msg, status = 400) => json({error: msg}, status);
const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64u = s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return Uint8Array.from(atob(s), c => c.charCodeAt(0)); };
const randToken = n => b64u(crypto.getRandomValues(new Uint8Array(n)));
const sha256 = async s => b64u(await crypto.subtle.digest('SHA-256', enc.encode(s)));
function safeEq(a, b){ if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; }
async function hashPassword(pw, saltB64){
  const salt = saltB64 ? fromB64u(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITER}, key, 256);
  return {hash: b64u(bits), salt: b64u(salt)};
}
function getCookie(req, name){
  const c = req.headers.get('Cookie') || '';
  for (const part of c.split(';')){ const [k, ...v] = part.trim().split('='); if (k === name) return v.join('='); }
  return null;
}
const sessionCookie = (token, maxAge) => `sid=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
const validEmail = e => typeof e === 'string' && e.length <= 120 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);
const validPass = p => typeof p === 'string' && p.length >= 8 && p.length <= 128;
const cleanName = n => (typeof n === 'string' ? n.trim().slice(0, 80) : '');
function cleanPerms(p){
  p = p && typeof p === 'object' ? p : {};
  const o = {tabs: {}, types: {}, ctrl: {}};
  TABS.forEach(k => { o.tabs[k] = !!(p.tabs || {})[k]; });
  TYPES.forEach(k => { o.types[k] = !!(p.types || {})[k]; });
  CTRLS.forEach(k => { o.ctrl[k] = !!(p.ctrl || {})[k]; });
  o.venue = !!p.venue; o.patch = !!p.patch; o.scenes = !!p.scenes;
  o.maxFix = Math.max(0, Math.min(96, parseInt(p.maxFix, 10) || 0));
  o.maxScenes = Math.max(0, Math.min(99, parseInt(p.maxScenes, 10) || 0));
  o.maxPerGroup = Math.max(1, Math.min(24, parseInt(p.maxPerGroup, 10) || 1));
  return o;
}
const publicUser = u => ({id: u.id, name: u.name, email: u.email, role: u.role, status: u.status, mustChange: !!u.must_change});
const parsePerms = u => { try{ return u.perms ? JSON.parse(u.perms) : null; }catch(e){ return null; } };

// ---------- base de datos ----------
async function getConfig(env){
  const row = await env.DB.prepare("SELECT value FROM config WHERE key = 'main'").first();
  let c = {}; try{ c = row ? JSON.parse(row.value) : {}; }catch(e){}
  return Object.assign({open: true, maxUsers: 10}, c);
}
async function getPlans(env){
  const row = await env.DB.prepare("SELECT value FROM config WHERE key = 'plans'").first();
  let saved = {}; try{ saved = row ? JSON.parse(row.value) : {}; }catch(e){}
  const out = {};
  PLAN_IDS.forEach(id => {
    const d = DEFAULT_PLANS[id], v = saved[id] || {};
    out[id] = {name: String(v.name || d.name).slice(0, 30), price: String(v.price ?? d.price).slice(0, 40), desc: String(v.desc ?? d.desc).slice(0, 200), perms: cleanPerms(v.perms || d.perms)};
  });
  return out;
}
// Agrega las columnas de planes si la base se creó con la versión anterior
let migrated = false;
async function migrate(env){
  if (migrated) return;
  for (const sql of ["ALTER TABLE users ADD COLUMN plan TEXT NOT NULL DEFAULT 'free'", 'ALTER TABLE users ADD COLUMN plan_request TEXT']){
    try{ await env.DB.prepare(sql).run(); }catch(e){ /* la columna ya existe */ }
  }
  migrated = true;
}
const countByStatus = async (env, status) => (await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE status = ? AND role = 'user'").bind(status).first()).n;
async function createSession(env, userId){
  const token = randToken(32), now = Date.now();
  await env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(now).run();
  await env.DB.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)').bind(await sha256(token), userId, now + SESSION_DAYS * 86400000).run();
  return sessionCookie(token, SESSION_DAYS * 86400);
}
async function getSessionUser(env, req){
  const sid = getCookie(req, 'sid'); if (!sid) return null;
  const row = await env.DB.prepare('SELECT u.*, s.expires_at AS s_exp FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?').bind(await sha256(sid)).first();
  if (!row || row.s_exp < Date.now()) return null;
  return row;
}
async function mePayload(env, u){
  const plans = await getPlans(env), plan = PLAN_IDS.includes(u.plan) ? u.plan : 'free';
  return {user: Object.assign(publicUser(u), {plan, planRequest: u.plan_request || null}), perms: u.role === 'owner' ? null : plans[plan].perms, plans};
}

// ---------- rutas ----------
export async function handleApi(request, env, parts){
  const method = request.method;
  // Protección CSRF: toda petición que cambia datos debe venir de la página (encabezado propio)
  if (method !== 'GET' && request.headers.get('X-Requested-With') !== 'simulador') return fail('Solicitud no permitida.', 403);
  if (!env.DB) return fail('Falta configurar la base de datos D1 (binding DB).', 500);
  await migrate(env);
  let body = {};
  if (method === 'POST' || method === 'PUT'){ try{ body = await request.json(); }catch(e){ body = {}; } }
  const route = parts.join('/');
  try{
    // Estado público: ¿ya existe el Owner?
    if (route === 'status' && method === 'GET'){
      const o = await env.DB.prepare("SELECT id FROM users WHERE role = 'owner' LIMIT 1").first();
      const cfg = await getConfig(env);
      return json({hasOwner: !!o, open: cfg.open});
    }
    // Configuración inicial del Owner (una sola vez, con la clave SETUP_KEY)
    if (route === 'setup' && method === 'POST'){
      if (!env.SETUP_KEY) return fail('Falta configurar la clave SETUP_KEY en Cloudflare.', 500);
      if (await env.DB.prepare("SELECT id FROM users WHERE role = 'owner' LIMIT 1").first()) return fail('El Owner ya fue creado.', 409);
      if (!safeEq(String(body.key || ''), String(env.SETUP_KEY))) return fail('La clave de configuración no es correcta.', 403);
      const name = cleanName(body.name), email = String(body.email || '').trim().toLowerCase();
      if (name.length < 3) return fail('Escribe tu nombre completo.');
      if (!validEmail(email)) return fail('Escribe un correo electrónico válido.');
      if (!validPass(body.password)) return fail('La contraseña debe tener al menos 8 caracteres.');
      const {hash, salt} = await hashPassword(body.password);
      const r = await env.DB.prepare("INSERT INTO users (name, email, pass_hash, pass_salt, role, status, created_at) VALUES (?, ?, ?, ?, 'owner', 'active', ?)").bind(name, email, hash, salt, Date.now()).run();
      const u = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(r.meta.last_row_id).first();
      return json(await mePayload(env, u), 200, {'Set-Cookie': await createSession(env, u.id)});
    }
    if (route === 'register' && method === 'POST'){
      const cfg = await getConfig(env);
      if (!cfg.open) return fail('El registro de nuevos usuarios está cerrado.', 403);
      if (await countByStatus(env, 'active') >= cfg.maxUsers) return fail('Ya no hay cupos disponibles. Comunícate con el administrador.', 403);
      if (await countByStatus(env, 'pending') >= 200) return fail('Hay demasiadas solicitudes pendientes. Intenta más tarde.', 429);
      const name = cleanName(body.name), email = String(body.email || '').trim().toLowerCase();
      const message = typeof body.message === 'string' ? body.message.trim().slice(0, 200) : '';
      if (name.length < 3) return fail('Escribe tu nombre completo.');
      if (!validEmail(email)) return fail('Escribe un correo electrónico válido.');
      if (!validPass(body.password)) return fail('La contraseña debe tener al menos 8 caracteres.');
      if (await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first()) return fail('Ese correo ya está registrado. Inicia sesión.', 409);
      const {hash, salt} = await hashPassword(body.password);
      // Las cuentas nuevas empiezan en el plan Gratuito; si el Owner lo activó, quedan aprobadas al instante
      const st = cfg.autoApprove ? 'active' : 'pending';
      const r = await env.DB.prepare("INSERT INTO users (name, email, pass_hash, pass_salt, role, status, message, created_at, plan) VALUES (?, ?, ?, ?, 'user', ?, ?, ?, 'free')").bind(name, email, hash, salt, st, message, Date.now()).run();
      const u = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(r.meta.last_row_id).first();
      return json(await mePayload(env, u), 200, {'Set-Cookie': await createSession(env, u.id)});
    }
    if (route === 'login' && method === 'POST'){
      const email = String(body.email || '').trim().toLowerCase(), now = Date.now();
      // Máximo 5 intentos fallidos cada 15 minutos por correo
      const tries = (await env.DB.prepare('SELECT COUNT(*) AS n FROM login_attempts WHERE email = ? AND at > ?').bind(email, now - 900000).first()).n;
      if (tries >= 5) return fail('Demasiados intentos. Espera 15 minutos e inténtalo de nuevo.', 429);
      const u = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
      const check = u ? await hashPassword(String(body.password || ''), u.pass_salt) : await hashPassword(String(body.password || ''));
      if (!u || !safeEq(check.hash, u.pass_hash)){
        await env.DB.prepare('INSERT INTO login_attempts (email, at) VALUES (?, ?)').bind(email, now).run();
        return fail('Correo o contraseña incorrectos.', 401);
      }
      await env.DB.prepare('DELETE FROM login_attempts WHERE email = ? OR at < ?').bind(email, now - 86400000).run();
      return json(await mePayload(env, u), 200, {'Set-Cookie': await createSession(env, u.id)});
    }
    if (route === 'logout' && method === 'POST'){
      const sid = getCookie(request, 'sid');
      if (sid) await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(await sha256(sid)).run();
      return json({ok: true}, 200, {'Set-Cookie': sessionCookie('', 0)});
    }

    // ----- desde aquí se necesita sesión -----
    const me = await getSessionUser(env, request);
    if (!me) return fail('Inicia sesión.', 401);
    if (route === 'me' && method === 'GET') return json(await mePayload(env, me));
    // El usuario pide cambiar de plan; el Owner lo asigna después de recibir el pago
    if (route === 'plan-request' && method === 'POST'){
      const plan = String(body.plan || '');
      if (!PLAN_IDS.includes(plan)) return fail('Plan no válido.');
      await env.DB.prepare('UPDATE users SET plan_request = ? WHERE id = ?').bind(plan === me.plan ? null : plan, me.id).run();
      return json({ok: true});
    }
    if (route === 'password' && method === 'POST'){
      const cur = await hashPassword(String(body.current || ''), me.pass_salt);
      if (!safeEq(cur.hash, me.pass_hash)) return fail('La contraseña actual no es correcta.', 403);
      if (!validPass(body.next)) return fail('La nueva contraseña debe tener al menos 8 caracteres.');
      const {hash, salt} = await hashPassword(body.next);
      await env.DB.prepare('UPDATE users SET pass_hash = ?, pass_salt = ?, must_change = 0 WHERE id = ?').bind(hash, salt, me.id).run();
      return json({ok: true});
    }

    // ----- panel de administración: solo el Owner -----
    if (parts[0] === 'admin'){
      if (me.role !== 'owner') return fail('Solo el Owner puede usar el panel.', 403);
      if (route === 'admin/state' && method === 'GET'){
        const cfg = await getConfig(env);
        const {results} = await env.DB.prepare("SELECT id, name, email, role, status, message, created_at, plan, plan_request FROM users ORDER BY created_at DESC").all();
        return json({config: cfg, plans: await getPlans(env), users: results.map(u => ({id: u.id, name: u.name, email: u.email, role: u.role, status: u.status, message: u.message, createdAt: u.created_at, plan: PLAN_IDS.includes(u.plan) ? u.plan : 'free', planRequest: u.plan_request || null}))});
      }
      if (route === 'admin/config' && method === 'PUT'){
        const cfg = {open: !!body.open, autoApprove: !!body.autoApprove, maxUsers: Math.max(0, Math.min(5000, parseInt(body.maxUsers, 10) || 0))};
        await env.DB.prepare("INSERT INTO config (key, value) VALUES ('main', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").bind(JSON.stringify(cfg)).run();
        return json(cfg);
      }
      if (route === 'admin/plans' && method === 'PUT'){
        const cur = await getPlans(env), inp = body.plans || {}, out = {};
        PLAN_IDS.forEach(id => { const v = inp[id] || cur[id];
          out[id] = {name: String(v.name || cur[id].name).trim().slice(0, 30), price: String(v.price || '').trim().slice(0, 40), desc: String(v.desc || '').trim().slice(0, 200), perms: cleanPerms(v.perms)}; });
        await env.DB.prepare("INSERT INTO config (key, value) VALUES ('plans', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").bind(JSON.stringify(out)).run();
        return json(out);
      }
      if (parts[1] === 'users' && parts[2]){
        const id = parseInt(parts[2], 10);
        const u = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(id).first();
        if (!u) return fail('Usuario no encontrado.', 404);
        if (u.role === 'owner') return fail('No se puede modificar al Owner desde aquí.', 403);
        const action = parts[3] || '';
        const cfg = await getConfig(env);
        if (action === 'approve' && method === 'POST'){
          if (await countByStatus(env, 'active') >= cfg.maxUsers) return fail(`Ya tienes ${cfg.maxUsers} usuarios activos. Sube el máximo para aprobar más.`, 409);
          await env.DB.prepare("UPDATE users SET status = 'active', perms = COALESCE(perms, ?) WHERE id = ?").bind(JSON.stringify(PERM_BASIC), id).run();
          return json({ok: true});
        }
        if (action === 'status' && method === 'POST'){
          const st = body.status === 'active' ? 'active' : 'blocked';
          if (st === 'active' && u.status !== 'active' && await countByStatus(env, 'active') >= cfg.maxUsers) return fail(`Ya tienes ${cfg.maxUsers} usuarios activos. Sube el máximo para activar a otro.`, 409);
          await env.DB.prepare('UPDATE users SET status = ?, perms = COALESCE(perms, ?) WHERE id = ?').bind(st, JSON.stringify(PERM_BASIC), id).run();
          if (st === 'blocked') await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(id).run();
          return json({ok: true});
        }
        if (action === 'plan' && method === 'POST'){
          const plan = String(body.plan || '');
          if (!PLAN_IDS.includes(plan)) return fail('Plan no válido.');
          await env.DB.prepare('UPDATE users SET plan = ?, plan_request = NULL WHERE id = ?').bind(plan, id).run();
          return json({ok: true});
        }
        if (action === 'reset' && method === 'POST'){
          const temp = randToken(9).replace(/[-_]/g, 'x').slice(0, 12);
          const {hash, salt} = await hashPassword(temp);
          await env.DB.prepare('UPDATE users SET pass_hash = ?, pass_salt = ?, must_change = 1 WHERE id = ?').bind(hash, salt, id).run();
          await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(id).run();
          return json({tempPassword: temp});
        }
        if (action === '' && method === 'DELETE'){
          await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(id).run();
          await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
          return json({ok: true});
        }
      }
    }
    return fail('Ruta no encontrada.', 404);
  }catch(e){
    return fail('Error del servidor. Revisa los registros de Cloudflare.', 500);
  }
}
