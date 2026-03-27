const crypto = require('crypto');
const express = require('express');
const db = require('../lib/db');

const DASHBOARD_SESSION_COOKIE = 'hke_dashboard_session';
const DASHBOARD_STATE_COOKIE = 'hke_dashboard_oauth_state';
const DASHBOARD_SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 30;
const DASHBOARD_STATE_TTL_MS = 1000 * 60 * 10;

const DEFAULT_BOT_MESSAGES = {
  welcome_message: 'Welcome {member}!',
  goodbye_message: 'Goodbye {member}',
  levelup_message: 'Congrats {user}, you reached level {level}!',
  reaction_role_dm_message: 'You got the role **{role}** in **{server}**.',
};

function toFlag(v) {
  return v ? 1 : 0;
}

function parseIntSafe(v, fallback = 0) {
  const parsed = Number.parseInt(v, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function parseRoleIds(csv) {
  return String(csv || '')
    .split(',')
    .map(x => x.trim())
    .filter(Boolean);
}

function parseResponses(row) {
  if (row.responses_json) {
    try {
      const parsed = JSON.parse(row.responses_json);
      if (Array.isArray(parsed)) {
        const out = parsed.map(x => String(x || '').trim()).filter(Boolean);
        if (out.length) return out;
      }
    } catch (_) {}
  }
  return String(row.response || '').split('||').map(x => x.trim()).filter(Boolean);
}

function normalizeAutoReplyPayload(payload) {
  const trigger = String(payload?.trigger || '').trim();
  const response = String(payload?.response || '').trim();
  const responses = Array.isArray(payload?.responses)
    ? payload.responses.map(x => String(x || '').trim()).filter(Boolean)
    : String(payload?.responsesText || '').split(/\r?\n/).map(x => x.trim()).filter(Boolean);
  const allowed = Array.isArray(payload?.allowed_role_ids)
    ? payload.allowed_role_ids.map(String).map(x => x.trim()).filter(Boolean)
    : parseRoleIds(payload?.allowed_role_ids);
  const disabledRoles = Array.isArray(payload?.disabled_role_ids)
    ? payload.disabled_role_ids.map(String).map(x => x.trim()).filter(Boolean)
    : parseRoleIds(payload?.disabled_role_ids);
  const excludedChannels = Array.isArray(payload?.excluded_channel_ids)
    ? payload.excluded_channel_ids.map(String).map(x => x.trim()).filter(Boolean)
    : parseRoleIds(payload?.excluded_channel_ids);
  const modeRaw = String(payload?.match_mode || 'exact').toLowerCase();
  const matchMode = modeRaw === 'contains' ? 'contains' : 'exact';
  const sendAsReply = payload?.send_as_reply === 0 ? 0 : 1;
  const pinging = payload?.pinging ? 1 : 0;
  const deleteTriggerMessage = payload?.delete_trigger_message ? 1 : 0;

  return {
    trigger,
    response: response || responses[0] || '',
    responses_json: responses.length ? JSON.stringify(responses) : null,
    allowed_role_ids: allowed.join(',') || null,
    disabled_role_ids: disabledRoles.join(',') || null,
    excluded_channel_ids: excludedChannels.join(',') || null,
    match_mode: matchMode,
    enabled: payload?.enabled === 0 ? 0 : 1,
    delete_trigger_message: deleteTriggerMessage,
    send_as_reply: sendAsReply,
    pinging,
  };
}

function normalizeCommandAliasPayload(payload) {
  const commandName = String(payload?.command_name || '').trim().toLowerCase();
  const aliasName = String(payload?.alias_name || '').trim().toLowerCase();
  return { command_name: commandName, alias_name: aliasName };
}

async function getBotMessages(guildId) {
  const rows = await db.all(
    'SELECT message_key, message_text FROM bot_messages WHERE guild_id = ? ORDER BY message_key ASC',
    [guildId]
  );
  const out = { ...DEFAULT_BOT_MESSAGES };
  for (const row of rows) out[row.message_key] = row.message_text;
  return out;
}

function authMiddleware(token) {
  return (req, res, next) => {
    if (req.path.startsWith('/auth/')) return next();
    const provided = req.headers['x-dashboard-token'] || req.query.token || '';
    if (token && provided !== token) {
      return res.status(401).json({ error: 'unauthorized' });
    }
    return next();
  };
}

function getDashboardAuthConfig() {
  const clientId = String(process.env.DISCORD_CLIENT_ID || process.env.DASHBOARD_CLIENT_ID || '').trim();
  const clientSecret = String(process.env.DISCORD_CLIENT_SECRET || process.env.DASHBOARD_CLIENT_SECRET || '').trim();
  const redirectUri = String(process.env.DISCORD_REDIRECT_URI || process.env.DASHBOARD_REDIRECT_URI || '').trim();
  return { clientId, clientSecret, redirectUri, isConfigured: Boolean(clientId && clientSecret && redirectUri) };
}

function getDashboardSessionSecret() {
  return String(process.env.DASHBOARD_SESSION_SECRET || process.env.DISCORD_CLIENT_SECRET || process.env.DASHBOARD_TOKEN || process.env.DISCORD_TOKEN || 'hke-dashboard-fallback-secret').trim();
}

function parseCookieHeader(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const idx = part.indexOf('=');
    if (idx <= 0) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (!key) continue;
    out[key] = decodeURIComponent(value || '');
  }
  return out;
}

function toBase64Url(value) {
  return Buffer.from(value).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function fromBase64Url(value) {
  const normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  const missing = normalized.length % 4;
  const padded = normalized + (missing ? '='.repeat(4 - missing) : '');
  return Buffer.from(padded, 'base64').toString('utf8');
}

function createSignedValue(payload, secret) {
  const body = toBase64Url(JSON.stringify(payload || {}));
  const sig = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  return body + '.' + sig;
}

function readSignedValue(value, secret) {
  const raw = String(value || '');
  const dot = raw.lastIndexOf('.');
  if (dot <= 0) return null;
  const body = raw.slice(0, dot);
  const sig = raw.slice(dot + 1);
  const expected = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  if (sig !== expected) return null;
  try {
    const parsed = JSON.parse(fromBase64Url(body));
    if (parsed && typeof parsed === 'object') {
      if (parsed.exp && Date.now() > Number(parsed.exp)) return null;
      return parsed;
    }
  } catch (_) {}
  return null;
}

function serializeCookie(name, value, options = {}) {
  const segments = [name + '=' + encodeURIComponent(String(value || ''))];
  if (options.maxAge != null) segments.push('Max-Age=' + Math.max(0, Math.floor(options.maxAge / 1000)));
  if (options.expires) segments.push('Expires=' + new Date(options.expires).toUTCString());
  segments.push('Path=' + (options.path || '/'));
  if (options.httpOnly) segments.push('HttpOnly');
  if (options.sameSite) segments.push('SameSite=' + options.sameSite);
  if (options.secure) segments.push('Secure');
  return segments.join('; ');
}

function getDashboardCookieOptions() {
  const redirectUri = String(process.env.DISCORD_REDIRECT_URI || process.env.DASHBOARD_REDIRECT_URI || '').trim();
  const secure = String(process.env.DASHBOARD_SECURE_COOKIE || '').trim() === '1' || redirectUri.startsWith('https://');
  return { path: '/', httpOnly: true, sameSite: 'Lax', secure };
}

function setCookie(res, name, value, req, extra = {}) {
  res.append('Set-Cookie', serializeCookie(name, value, { ...getDashboardCookieOptions(req), ...extra }));
}

function clearCookie(res, name, req) {
  res.append('Set-Cookie', serializeCookie(name, '', { ...getDashboardCookieOptions(req), expires: 0, maxAge: 0 }));
}

function setDashboardState(res, req, payload) {
  const signed = createSignedValue({ ...payload, exp: Date.now() + DASHBOARD_STATE_TTL_MS }, getDashboardSessionSecret());
  setCookie(res, DASHBOARD_STATE_COOKIE, signed, req, { maxAge: DASHBOARD_STATE_TTL_MS });
}

function readDashboardState(req) {
  const cookies = parseCookieHeader(req.headers.cookie || '');
  return readSignedValue(cookies[DASHBOARD_STATE_COOKIE], getDashboardSessionSecret());
}

function setDashboardSession(res, req, user) {
  const signed = createSignedValue({ ...user, exp: Date.now() + DASHBOARD_SESSION_TTL_MS }, getDashboardSessionSecret());
  setCookie(res, DASHBOARD_SESSION_COOKIE, signed, req, { maxAge: DASHBOARD_SESSION_TTL_MS });
}

function readDashboardSession(req) {
  const cookies = parseCookieHeader(req.headers.cookie || '');
  return readSignedValue(cookies[DASHBOARD_SESSION_COOKIE], getDashboardSessionSecret());
}

function getAuthenticatedDashboardUser(req) {
  const session = readDashboardSession(req);
  if (!session || !session.id) return null;
  return { id: String(session.id), username: String(session.username || ''), global_name: String(session.global_name || ''), avatar: String(session.avatar || '') };
}

function buildDashboardReturnUrl(dashboardToken = '', extraParams = {}) {
  const params = new URLSearchParams();
  if (dashboardToken) params.set('token', dashboardToken);
  for (const [key, value] of Object.entries(extraParams || {})) {
    if (value == null || value === '') continue;
    params.set(key, String(value));
  }
  const query = params.toString();
  return '/' + (query ? ('?' + query) : '');
}

async function exchangeDiscordCode(code, config) {
  const body = new URLSearchParams({ client_id: config.clientId, client_secret: config.clientSecret, grant_type: 'authorization_code', code: String(code || ''), redirect_uri: config.redirectUri, scope: 'identify' });
  const response = await fetch('https://discord.com/api/oauth2/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
  if (!response.ok) {
    const responseText = await response.text().catch(() => '');
    throw new Error('discord_token_exchange_failed:' + (responseText || response.status));
  }
  return response.json();
}

async function fetchDiscordUser(accessToken) {
  const response = await fetch('https://discord.com/api/users/@me', { headers: { Authorization: 'Bearer ' + accessToken } });
  if (!response.ok) {
    const responseText = await response.text().catch(() => '');
    throw new Error('discord_user_fetch_failed:' + (responseText || response.status));
  }
  return response.json();
}

async function processDiscordAuthCallback(req, res) {
  const authConfig = getDashboardAuthConfig();
  const savedState = readDashboardState(req);
  const dashboardToken = String(req.query.token || savedState?.dashboardToken || '');
  const fail = (code) => res.redirect(buildDashboardReturnUrl(dashboardToken, { auth_error: code }));
  if (!authConfig.isConfigured) return fail('oauth_not_configured');
  if (!savedState || !savedState.nonce || String(req.query.state || '') !== String(savedState.nonce)) return fail('invalid_state');
  const code = String(req.query.code || '');
  if (!code) return fail('missing_code');
  try {
    const tokenPayload = await exchangeDiscordCode(code, authConfig);
    const user = await fetchDiscordUser(tokenPayload.access_token);
    setDashboardSession(res, req, { id: user.id, username: user.username, global_name: user.global_name || '', avatar: user.avatar || '' });
    clearCookie(res, DASHBOARD_STATE_COOKIE, req);
    return res.redirect(buildDashboardReturnUrl(dashboardToken));
  } catch (_) {
    clearCookie(res, DASHBOARD_STATE_COOKIE, req);
    return fail('discord_login_failed');
  }
}

function buildDashboardHtml() {
  return `<!doctype html><html lang="ar" dir="rtl"><head>
  <meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>لوحة تحكم HKE</title>
  <style>
    :root{
      --bg:#0b1220;--bg2:#111827;--panel:#0f172a;--line:#263247;--line2:#334155;
      --txt:#f8fafc;--muted:#94a3b8;--accent:#38bdf8;--ok:#22c55e;--warn:#f59e0b;
      --radius-sm:10px;--radius-md:18px;--radius-lg:26px;
      --scroll-track:rgba(15,23,42,.95);--scroll-thumb:#1f5b82;--scroll-thumb-hover:#38bdf8;
    }
    *{box-sizing:border-box}
    *{
      scrollbar-width:thin;
      scrollbar-color:var(--scroll-thumb) var(--scroll-track)
    }
    *::-webkit-scrollbar{width:10px;height:10px}
    *::-webkit-scrollbar-track{background:var(--scroll-track);border-radius:999px}
    *::-webkit-scrollbar-thumb{
      background:linear-gradient(180deg, #184868, var(--scroll-thumb));
      border-radius:999px;
      border:2px solid var(--scroll-track)
    }
    *::-webkit-scrollbar-thumb:hover{
      background:linear-gradient(180deg, #2a76a5, var(--scroll-thumb-hover))
    }
    body{
      font-family:Segoe UI,Arial;
      background:
        radial-gradient(1200px 500px at 0% -10%, #0b3b7a 0%, transparent 60%),
        radial-gradient(900px 500px at 100% 0%, #0b6c8a 0%, transparent 60%),
        var(--bg);
      color:var(--txt);margin:0
    }
    .w{padding:18px;max-width:1320px;margin:auto;overflow-x:hidden}
    h2{margin:0 0 8px 0;letter-spacing:.3px}
    .c{
      border:1px solid var(--line2);
      background:linear-gradient(180deg, rgba(17,24,39,.95), rgba(11,18,32,.95));
      border-radius:var(--radius-lg);padding:14px;margin:12px 0;
      box-shadow:0 10px 28px rgba(0,0,0,.22);
      width:100%;
      max-width:100%;
      overflow:hidden
    }
    .c h3{
      margin:0 0 12px 0;font-size:16px;
      border-left:3px solid var(--accent);padding-left:10px
    }
    .r{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
    .r > input,.r > select{flex:1 1 220px;min-width:180px}
    .m{color:var(--muted);font-size:12px}
    label{display:block;margin:8px 0 6px;color:#cbd5e1;font-size:12px}
    input,textarea,select,button{
      background:var(--panel);color:var(--txt);border:1px solid var(--line);
      border-radius:var(--radius-md);padding:9px 10px;outline:none
    }
    input:focus,textarea:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 2px rgba(56,189,248,.18)}
    textarea{width:100%;min-height:88px;resize:vertical}
    select[multiple]{min-height:140px}
    button{cursor:pointer;font-weight:600;transition:.18s}
    button:hover{transform:translateY(-1px);border-color:var(--accent)}
    #saveSettings,#saveMsgs,#saveReply,#addBlack,#setRoleLevel,#creditSet,#creditAdd,#creditRefresh{
      background:linear-gradient(180deg, #0f2f4a, #12324d);
      border-color:#1f516b
    }
    #guild{width:100%;font-weight:600}
    table{width:100%;border-collapse:collapse;border:1px solid var(--line);border-radius:var(--radius-md);overflow:hidden}
    th,td{border-bottom:1px solid var(--line);padding:9px 8px;text-align:left;vertical-align:top}
    th{background:#0b1423;color:#cbd5e1;font-size:12px;letter-spacing:.2px}
    tr:nth-child(even) td{background:rgba(148,163,184,.04)}
    code{background:#0b1423;border:1px solid var(--line);border-radius:12px;padding:2px 6px}
    .roles-checklist{
      border:1px solid var(--line);
      border-radius:var(--radius-md);
      padding:8px;
      max-height:180px;
      overflow:auto;
      overscroll-behavior:contain;
      background:rgba(11,20,35,.55)
    }
    .search-control{display:inline-flex;align-items:center;gap:8px;max-width:100%}
    .inline-select-search{display:grid !important;grid-template-columns:minmax(0,1fr) auto auto !important;align-items:center;gap:8px;width:100%}
    .inline-select-search select{width:100%;min-width:0;max-width:none}
    .inline-select-search .search-control{flex:0 0 auto}
    .inline-select-search .search-pop{width:min(180px, 42vw)}
    .search-toggle-btn{
      min-width:56px;
      width:56px;
      height:42px;
      padding:0 10px;
      border-radius:999px;
      background:linear-gradient(180deg, #173247, #122537);
      border-color:#27506c;
      display:inline-flex;
      align-items:center;
      justify-content:center;
      font-size:13px;
      line-height:1;
      color:#dbeafe;
      overflow:hidden
    }
    .search-pop{
      display:none;
      width:min(220px, 62vw);
      margin:0;
      animation:fadeInSearch .14s ease
    }
    .search-control.open .search-pop{display:block}
    @keyframes fadeInSearch{
      from{opacity:0;transform:translateY(-2px)}
      to{opacity:1;transform:translateY(0)}
    }
    .role-check{
      display:flex;
      align-items:center;
      gap:8px;
      padding:6px 4px;
      border-radius:8px;
      cursor:pointer
    }
    .role-check:hover{background:rgba(148,163,184,.08)}
    .role-check input{width:auto;margin:0}
    .role-check .rid{color:var(--muted);font-size:11px}
    .channel-checklist{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px}
    .channel-card{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:12px;padding:10px 12px;border:1px solid var(--line);border-radius:var(--radius-md);background:rgba(15,23,42,.7);direction:ltr;min-height:62px}
    .channel-card:hover{border-color:var(--accent);background:rgba(20,31,56,.9)}
    .channel-meta{display:flex;flex-direction:column;gap:4px;min-width:0;width:100%;text-align:right;direction:rtl}
    .channel-name{display:block;width:100%;font-weight:700;color:#e2e8f0;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;line-height:1.4}
    .channel-sub{display:block;width:100%;font-size:11px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .channel-toggle{width:18px;height:18px;flex:0 0 auto;margin:0}
    .reply-responses-wrap{
      display:flex;
      flex-direction:column;
      gap:8px
    }
    .reply-response-item{
      border:1px solid var(--line);
      border-radius:var(--radius-md);
      padding:8px;
      background:rgba(11,20,35,.45)
    }
    .reply-response-head{
      display:flex;
      align-items:center;
      justify-content:space-between;
      margin-bottom:6px;
      color:#cbd5e1;
      font-size:12px
    }
    .reply-response-item textarea{
      min-height:72px
    }
    .reply-response-remove{
      background:#2a1220;
      border-color:#5b1d35
    }
    .reply-modal{
      position:fixed;
      inset:0;
      background:rgba(2,6,23,.72);
      backdrop-filter:blur(4px);
      display:none;
      align-items:center;
      justify-content:center;
      z-index:10001;
      padding:16px
    }
    .reply-modal.show{display:flex}
    .reply-modal-box{
      width:min(960px,97vw);
      max-height:92vh;
      overflow:auto;
      overscroll-behavior:contain;
      border:1px solid var(--line2);
      background:linear-gradient(180deg, rgba(30,35,52,.98), rgba(20,24,38,.98));
      border-radius:var(--radius-lg);
      padding:12px
    }
    .reply-modal-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}
    .reply-modal-close{min-width:36px;padding:6px 10px;background:#2b1625;border-color:#63304a}
    .reply-modal-options{display:flex;align-items:center;gap:18px;margin:8px 0}
    .reply-modal-options .opt{display:flex;align-items:center;gap:6px;margin:0}
    .reply-vars{border:1px dashed var(--line);border-radius:var(--radius-md);padding:8px;margin:8px 0}
    .reply-roles-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
    .reply-modal-actions{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:10px}
    .reply-btns{display:flex;gap:8px}
    .settings-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}
    .settings-field{display:flex;flex-direction:column;gap:6px}
    .settings-field label{margin:0;font-size:12px;color:#cbd5e1}
    .settings-field input,.settings-field select{width:100%}
    .settings-actions{grid-column:1 / -1;display:flex;justify-content:flex-start}
    .settings-head-note{display:none}
    body.auth-locked{overflow:hidden}
    .auth-overlay{
      position:fixed;
      inset:0;
      background:rgba(2,6,23,.72);
      backdrop-filter:blur(4px);
      display:none;
      align-items:center;
      justify-content:center;
      z-index:9999
    }
    .auth-overlay.show{display:flex}
    .auth-card{
      width:min(92vw,460px);
      border:1px solid var(--line2);
      background:linear-gradient(180deg, rgba(17,24,39,.98), rgba(11,18,32,.98));
      border-radius:var(--radius-lg);
      padding:16px;
      box-shadow:0 12px 32px rgba(0,0,0,.35)
    }
    .auth-card h3{margin:0 0 8px 0}
    .auth-actions{display:flex;gap:8px;margin-top:10px}
    .auth-actions button{flex:1}
    .hub-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:12px 0}
    .hub-card{border:1px solid var(--line2);background:linear-gradient(180deg, rgba(30,35,52,.96), rgba(20,24,38,.96));border-radius:var(--radius-lg);padding:12px;min-height:118px;display:flex;flex-direction:column;justify-content:space-between;gap:8px;overflow:hidden}
    .hub-title{font-weight:700;color:#eef2ff;overflow-wrap:anywhere;word-break:break-word}
    .hub-sub{font-size:12px;color:#a5b4fc;overflow-wrap:anywhere;word-break:break-word}
    .hub-go{background:#232a3a;border:1px solid #3a4256;border-radius:var(--radius-md);padding:8px 10px;text-align:center;font-weight:700;width:100%}
    .section-hidden{display:none !important}
    .section-modal{position:fixed;inset:0;background:rgba(2,6,23,.72);backdrop-filter:blur(3px);display:none;align-items:flex-start;justify-content:center;z-index:9998;padding:20px;overflow:auto;overscroll-behavior:contain}
    .section-modal.show{display:flex}
    .section-shell{width:min(1200px,98vw);border:1px solid var(--line2);background:linear-gradient(180deg, rgba(17,24,39,.98), rgba(11,18,32,.98));border-radius:var(--radius-lg);padding:12px}
    .section-shell-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}
    .section-shell-close{background:#3b1f2d;border-color:#7a304f}
    .command-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
    .command-card{border:1px solid var(--line2);background:linear-gradient(180deg, rgba(30,35,52,.96), rgba(20,24,38,.96));border-radius:var(--radius-lg);padding:12px;display:flex;flex-direction:column;gap:10px}
    .command-card-head{display:flex;align-items:center;justify-content:space-between;gap:8px}
    .command-card-title{font-weight:700}
    .command-card-sub{font-size:12px;color:#a5b4fc}
    .command-card-actions{display:flex;gap:8px;flex-wrap:wrap}
    .command-card-actions button{flex:1 1 120px}
    .toggle-chip{display:flex;align-items:center;gap:6px;font-size:12px;color:#cbd5e1}
    .command-modal-body{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
    .multi-input-list{display:flex;flex-direction:column;gap:8px}
    .multi-input-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;align-items:center}
    .multi-input-row input,.multi-input-row select{width:100%;min-width:0}
    .mini-btn{min-width:56px;width:56px;height:42px;padding:0 10px;font-size:12px;white-space:nowrap;flex:0 0 auto}
    .add-channel-btn{min-width:100%;width:100%;height:auto;padding:9px 12px;font-size:14px}
    @media (max-width: 760px){
      .w{padding:10px}
      .c{padding:10px;border-radius:var(--radius-md)}
      h2{font-size:24px;line-height:1.2}
      .r > input,.r > select{flex:1 1 100%}
      .r > button{flex:1 1 100%}
      .hub-grid{grid-template-columns:1fr;gap:10px}
      .command-modal-body{grid-template-columns:1fr}
      .hub-card{min-height:auto;padding:10px}
      .hub-title{font-size:18px}
      .hub-sub{font-size:13px}
      table{display:block;overflow-x:auto;white-space:nowrap}
      .section-shell{width:100%;padding:10px}
      .settings-grid{grid-template-columns:1fr}
      .reply-roles-grid{grid-template-columns:1fr}
      .reply-modal-actions{flex-direction:column;align-items:flex-start}
      .reply-modal{padding:8px}
      .reply-modal-box{width:100%;max-height:94vh;padding:10px}
    }
  </style></head><body>
  <div id="authOverlay" class="auth-overlay">
    <div class="auth-card">
      <h3>تسجيل الدخول</h3>
      <div class="auth-actions">
        <button id="authSubmit" type="button">سجل الدخول</button>
      </div>
      <div id="authErr" class="m" style="color:#fca5a5;margin-top:8px;display:none"></div>
    </div>
  </div>
  <div id="sectionModal" class="section-modal">
    <div class="section-shell">
      <div class="section-shell-head">
        <b id="sectionModalTitle">القسم</b>
        <button id="sectionModalClose" class="section-shell-close" type="button">إغلاق</button>
      </div>
      <div id="sectionModalBody"></div>
    </div>
  </div>
  <div class="w">
  <h2>لوحة تحكم HKE</h2><div id="status" class="m">جاري التحميل...</div>
  <div class="r" style="justify-content:space-between;gap:12px"><div id="authSummary" class="m">التحقق من الجلسة...</div><button id="changeUser" type="button">تسجيل الخروج</button></div>
  <div class="c"><label>السيرفر</label><div class="m">اختر السيرفر الذي تريد تعديل إعداداته.</div><select id="guild"></select></div>

  <div class="hub-grid" id="sectionHub">
    <div class="hub-card"><div class="hub-title">الإعدادات</div><div class="hub-sub">إعدادات السيرفر الأساسية</div><button class="hub-go" data-go="settingsCard">فتح</button></div>
    <div class="hub-card"><div class="hub-title">رسائل البوت</div><div class="hub-sub">الترحيب والمغادرة والليفل</div><button class="hub-go" data-go="messagesCard">فتح</button></div>
    <div class="hub-card"><div class="hub-title">الرد التلقائي</div><div class="hub-sub">إدارة الردود والكلمات</div><button class="hub-go" data-go="repliesCard">فتح</button></div>
    <div class="hub-card"><div class="hub-title">اللفلات</div><div class="hub-sub">إعدادات رتب الليفل</div><button class="hub-go" data-go="levelsCard">فتح</button></div>
    <div class="hub-card"><div class="hub-title">الكريديت</div><div class="hub-sub">إدارة رصيد الأعضاء</div><button class="hub-go" data-go="creditsCard">فتح</button></div>
    <div class="hub-card"><div class="hub-title">الأسماء المختصرة</div><div class="hub-sub">إضافة Alias للأوامر</div><button class="hub-go" data-go="aliasesCard">فتح</button></div>
    <div class="hub-card"><div class="hub-title">إعدادات الأوامر</div><div class="hub-sub">تفعيل وتعطيل وتخصيص أوامر البوت</div><button class="hub-go" data-go="commandsCard">فتح</button></div>
  </div>

  <div class="c">
      <h3>الإعدادات الأساسية</h3><div class="m">اختر القنوات والرتب المطلوبة لتفعيل ميزات البوت في السيرفر.</div>
      <div class="m" style="margin:8px 0 10px 0;line-height:1.7">
        welcome_channel_id: قناة رسالة الترحيب.<br>
        goodbye_channel_id: قناة رسالة المغادرة.<br>
        levelup_channel_id: قناة إعلان رفع الليفل.<br>
        muted_role_id: الرتبة المستخدمة للميوت.<br>
        log_*_channel_id: قنوات اللوقات المختلفة.
      </div>
    <div class="r">
      <input id="welcome_channel_id" placeholder="ID قناة الترحيب" />
      <input id="goodbye_channel_id" placeholder="ID قناة المغادرة" />
      <input id="levelup_channel_id" placeholder="ID قناة الليفل" />
        <input id="muted_role_id" placeholder="ID رتبة الميوت" />
      <input id="ticket_category_id" placeholder="ID كاتيجوري التذاكر" />
    </div><div class="r">
      <input id="log_roles_channel_id" placeholder="ID لوق الرتب" />
      <input id="log_rooms_channel_id" placeholder="ID لوق الرومات" />
      <input id="log_bans_channel_id" placeholder="ID لوق الباند" />
      <input id="log_time_channel_id" placeholder="ID لوق التايم" />
      <input id="log_kick_channel_id" placeholder="ID لوق الكيك" />
      <input id="log_message_edit_channel_id" placeholder="ID لوق تعديل الرسائل" />
      <input id="log_message_delete_channel_id" placeholder="ID لوق حذف الرسائل" />
    </div><div class="r">
      <select id="stats_enabled"><option value="1">تفعيل الإحصائيات</option><option value="0">تعطيل الإحصائيات</option></select>
      <select id="automod_spam_enabled"><option value="1">منع السبام: تشغيل</option><option value="0">منع السبام: إيقاف</option></select>
      <select id="automod_links_enabled"><option value="1">منع الروابط: تشغيل</option><option value="0">منع الروابط: إيقاف</option></select>
      <select id="automod_caps_enabled"><option value="1">منع الحروف الكبيرة: تشغيل</option><option value="0">منع الحروف الكبيرة: إيقاف</option></select>
      <select id="auto_reply_delete_trigger"><option value="0">حذف رسالة المستخدم بعد الرد: إيقاف</option><option value="1">حذف رسالة المستخدم بعد الرد: تشغيل</option></select>
      <input id="automod_warn_threshold" type="number" placeholder="عدد التحذيرات قبل الإجراء" />
      <button id="saveSettings">حفظ الإعدادات</button>
    </div>
  </div>

  <div class="c">
    <h3>رسائل البوت</h3><div class="m">اكتب الرسائل التي يرسلها البوت. المتغيرات المتاحة: {user} {member} {server} {level} {role}</div>
    <label>رسالة الترحيب (تُرسل عند دخول عضو)</label><textarea id="msg_welcome_message"></textarea>
    <label>رسالة المغادرة (تُرسل عند خروج عضو)</label><textarea id="msg_goodbye_message"></textarea>
    <label>رسالة رفع الليفل (تُرسل عند زيادة مستوى عضو)</label><textarea id="msg_levelup_message"></textarea>
    <label>رسالة الخاص للرتبة التفاعلية (تُرسل في DM عند أخذ رتبة تفاعلية)</label><textarea id="msg_reaction_role_dm_message"></textarea>
    <button id="saveMsgs">حفظ الرسائل</button>
  </div>

    <div class="c">
      <h3>إعدادات الأوامر</h3>
      <div class="m">من هنا تفعّل أو تعطل الأوامر، وتدخل على إعدادات كل أمر من نافذة منبثقة.</div>
      <div class="r" style="margin:10px 0 12px 0">
        <input id="custom_prefix" placeholder="البريفكس العام - اتركه فارغًا لإلغائه" />
        <button id="savePrefixConfig" type="button">حفظ البريفكس</button>
      </div>
        <div class="r" style="margin:0 0 12px 0">
          <div id="commandSearchWrap" class="search-control">
            <button id="commandSearchToggle" type="button" class="search-toggle-btn">بحث</button>
            <input id="commandSearch" class="search-pop" placeholder="ابحث عن أمر..." />
          </div>
        </div>
      <div id="commandCards" class="command-grid"></div>
    </div>

  <div class="c"><h3>رتب السيرفر</h3>
    <div class="r" style="margin-bottom:8px;">
      <button id="toggleRoles">إخفاء الرتب</button>
      <span id="rolesCount" class="m"></span>
    </div>
    <div id="rolesWrap">
      <table><thead><tr><th>اسم الرتبة</th><th>ID</th><th>الترتيب</th></tr></thead><tbody id="roles"></tbody></table>
    </div>
  </div>

      <div class="c">
    <h3>الردود التلقائية</h3><div class="m">إدارة الردود من القائمة، والإضافة أو التعديل يتم من نافذة منبثقة.</div>
    <div class="r" style="justify-content:space-between;gap:10px;margin-bottom:8px">
      <button id="openReplyModal" type="button">+ إضافة رد تلقائي</button>
      <button id="refreshReplies" type="button">تحديث القائمة</button>
    </div>
    <table><thead><tr><th>الرسالة</th><th>إجراء</th></tr></thead><tbody id="replies"></tbody></table>

    <div id="replyModal" class="reply-modal" aria-hidden="true">
      <div class="reply-modal-box">
        <div class="reply-modal-head">
          <button id="closeReplyModal" class="reply-modal-close" type="button">×</button>
          <h4 id="replyModalTitle">إضافة رد تلقائي</h4>
        </div>

        <label>الرسالة</label>
        <input id="reply_trigger" placeholder="الرسالة" />

        <div class="reply-modal-options">
          <label class="opt"><input id="reply_contains" type="checkbox" /> البحث في الجملة كاملة</label>
          <label class="opt"><input id="reply_enabled" type="checkbox" checked /> تفعيل الرد</label>
          <label class="opt"><input id="reply_send_as_reply" type="checkbox" checked /> إرسال كرد</label>
          <label class="opt" id="replyPingingWrap"><input id="reply_pinging" type="checkbox" /> تنبيه المستخدم</label>
          <label class="opt"><input id="reply_delete_trigger" type="checkbox" /> حذف رسالة المستخدم بعد الرد</label>
        </div>

        <label>الرد</label>
        <div id="reply_responses_wrap" class="reply-responses-wrap"></div>
        <div class="r"><button id="addReplyResponse" type="button">+ إضافة رد عشوائي</button></div>

        <div class="reply-vars">
          <div class="m"><b>المتغيرات</b></div>
          <div class="m"><code>[user]</code> الإشارة إلى الكاتب</div>
          <div class="m"><code>[userName]</code> يظهر اسم العضو بدون إشارة</div>
          <div class="m"><code>[invites]</code> عدد دعوات العضو</div>
        </div>

        <div class="reply-roles-grid">
          <div>
            <label>الرولات المفعلة</label>
            <div id="reply_roles" class="roles-checklist"></div>
          </div>
          <div>
            <label>الرولات المعطلة</label>
            <div id="reply_roles_disabled" class="roles-checklist"></div>
          </div>
        </div>

        <div class="reply-roles-grid">
          <div>
            <label>الرومات المستثناة من الرد</label>
            <div id="reply_channels" class="roles-checklist"></div>
          </div>
          <div>
            <label>ملحوظة</label>
            <div class="m">أي روم يتم اختياره هنا لن يرسل البوت فيه هذا الرد.</div>
          </div>
        </div>

        <div class="reply-modal-actions">
          <div id="editState" class="m">الوضع الحالي: إنشاء رد جديد</div>
          <div class="reply-btns">
            <button id="clearEdit" type="button">إلغاء</button>
            <button id="saveReply" type="button">حفظ التغييرات</button>
          </div>
        </div>

        <input id="reply_match_mode" type="hidden" value="exact" />
      </div>
    </div>
  </div>
  <div id="commandModal" class="reply-modal" aria-hidden="true">
    <div class="reply-modal-box">
      <div class="reply-modal-head">
        <button id="closeCommandModal" class="reply-modal-close" type="button">×</button>
        <h4 id="commandModalTitle">إعدادات الأمر</h4>
      </div>
      <div id="commandModalBody" class="command-modal-body"></div>
      <div class="reply-modal-actions">
        <div class="reply-btns">
          <button id="saveCommandConfig" type="button">حفظ الإعدادات</button>
        </div>
      </div>
    </div>
  </div>
<div class="c">
    <h3>قائمة الكلمات الممنوعة</h3><div class="m">أي كلمة هنا تعتبر كلمة ممنوعة ضمن نظام الحماية.</div>
    <div class="r"><input id="black_word" placeholder="اكتب كلمة لإضافتها للحظر" /><button id="addBlack">إضافة</button></div>
    <div id="blackListBox" class="m"></div>
  </div>

  <div class="c">
    <h3>رتب الليفل</h3><div class="m">اربط مستوى معين برتبة: عند الوصول للمستوى، يحصل العضو على الرتبة تلقائيًا.</div>
    <div class="r">
      <input id="role_level_value" type="number" placeholder="المستوى" />
      <select id="role_level_role"></select>
      <button id="setRoleLevel">حفظ الربط</button>
    </div>
    <div id="roleLevelsBox" class="m"></div>
  </div>

  <div class="c">
    <h3>إدارة الكريديت</h3><div class="m">تعديل رصيد عضو معين أو إضافة/خصم مبلغ من رصيده.</div>
    <div class="m" style="margin:8px 0 10px 0;line-height:1.7">
      ID المستخدم: اكتب معرف الشخص المراد تعديل رصيده.<br>
      تعيين الرصيد: يضبط الرصيد النهائي على الرقم المكتوب.<br>
      إضافة/خصم: يزيد أو ينقص من الرصيد الحالي (بالقيمة الموجبة/السالبة).
    </div>
    <div class="r">
      <input id="credit_user" placeholder="ID المستخدم" />
      <input id="credit_amount" type="number" placeholder="المبلغ" />
      <button id="creditSet">تعيين الرصيد</button>
      <button id="creditAdd">إضافة/خصم</button>
      <button id="creditRefresh">تحديث</button>
    </div>
    <table><thead><tr><th>#</th><th>المستخدم</th><th>الرصيد</th></tr></thead><tbody id="creditRows"></tbody></table>
  </div>

  <div class="c">
    <h3>ألياسات الأوامر</h3><div class="m">اختَر أمرًا ثم أضف له كلمة جديدة. هذه الكلمة تعمل في هذا السيرفر فقط.</div>
    <div class="r">
      <select id="alias_command"></select>
      <input id="alias_name" placeholder="الكلمة الجديدة للأمر" />
      <button id="aliasAdd">إضافة الكلمة</button>
      <button id="aliasRefresh">تحديث</button>
    </div>
    <table><thead><tr><th>الأمر</th><th>الكلمة</th><th>الإجراء</th></tr></thead><tbody id="aliasRows"></tbody></table>
  </div>

  <script>
    const urlParams = new URLSearchParams(location.search);
    const token = urlParams.get('token') || '';
    const authError = urlParams.get('auth_error') || '';
    let authUser = null;
    const q = id => document.getElementById(id);
    let guildId = null; let editingReplyId = null;
    let editingCommandKey = null;
    let currentSettings = {};
    let availableCommands = [];
    let guildChannels = [];
    const roleNameById = new Map();
    const channelNameById = new Map();
    const MSG_KEYS = ['welcome_message','goodbye_message','levelup_message','reaction_role_dm_message'];
    const CHANNEL_FIELD_IDS = ['welcome_channel_id','goodbye_channel_id','levelup_channel_id','cmd_channel_id','cmd_admin_channel_id','log_roles_channel_id','log_rooms_channel_id','log_bans_channel_id','log_time_channel_id','log_kick_channel_id','log_message_edit_channel_id','log_message_delete_channel_id'];
    const SETTINGS_FIELDS = [
      ['welcome_channel_id', 'قناة الترحيب'],
      ['goodbye_channel_id', 'قناة المغادرة'],
      ['levelup_channel_id', 'قناة الليفل'],
      ['muted_role_id', 'معرف رتبة الميوت'],
      ['ticket_category_id', 'معرف كاتيجوري التذاكر'],
      ['stats_enabled', 'تفعيل الإحصائيات'],
      ['auto_reply_delete_trigger', 'حذف رسالة المستخدم بعد الرد'],
      ['automod_warn_threshold', 'حد التحذيرات'],
      ['log_roles_channel_id', 'لوق الرتب'],
      ['log_rooms_channel_id', 'لوق الرومات'],
      ['log_bans_channel_id', 'لوق الباند'],
      ['log_time_channel_id', 'لوق التايم'],
      ['log_kick_channel_id', 'لوق الكيك'],
      ['log_message_edit_channel_id', 'لوق تعديل الرسائل'],
      ['log_message_delete_channel_id', 'لوق حذف الرسائل'],
      ['automod_spam_enabled', 'منع السبام'],
      ['automod_links_enabled', 'منع الروابط'],
      ['automod_caps_enabled', 'منع الحروف الكبيرة'],
    ];
    const COMMAND_CONFIGS = {
      t: {
        title: 'أمر t',
        sub: 'إعدادات التوب في الشات والفويس',
        enabledKey: 'command_t_enabled',
        fields: [
          { key: 'command_t_require_prefix', label: 'يتطلب بريفكس', type: 'select', options: [['0', 'لا'], ['1', 'نعم']] },
          { key: 'command_t_channel_mode', label: 'مكان عمل الأمر', type: 'select', options: [['any', 'أي روم'], ['selected', 'رومات معينة فقط']] },
          { key: 'command_t_channel_ids', label: 'الرومات المسموحة', type: 'channels' },
          { key: 't_text_metric', label: 'عرض التكست', type: 'select', options: [['xp', 'XP'], ['messages', 'عدد الرسائل']] },
          { key: 't_voice_metric', label: 'عرض الفويس', type: 'select', options: [['xp', 'XP'], ['hours', 'عدد الساعات']] },
        ],
      },
      r: {
        title: 'أمر r',
        sub: 'إعدادات شكل الرانك والمقاييس المعروضة',
        enabledKey: 'command_r_enabled',
        fields: [
          { key: 'command_r_require_prefix', label: 'يتطلب بريفكس', type: 'select', options: [['0', 'لا'], ['1', 'نعم']] },
          { key: 'command_r_channel_mode', label: 'مكان عمل الأمر', type: 'select', options: [['any', 'أي روم'], ['selected', 'رومات معينة فقط']] },
          { key: 'command_r_channel_ids', label: 'الرومات المسموحة', type: 'channels' },
          { key: 'r_style', label: 'شكل الأمر', type: 'select', options: [['image', 'صورة'], ['embed', 'Embed']] },
          { key: 'r_text_metric', label: 'عرض التكست', type: 'select', options: [['xp', 'XP'], ['messages', 'عدد الرسائل'], ['both', 'الاثنين']] },
          { key: 'r_voice_metric', label: 'عرض الفويس', type: 'select', options: [['xp', 'XP'], ['hours', 'عدد الساعات'], ['both', 'الاثنين']] },
        ],
      },
      giveaway: {
        title: 'أمر giveaway',
        sub: 'إعدادات الإيموجي ورسالة الفائزين',
        enabledKey: '',
        fields: [
          { key: 'emoji', label: 'إيموجي الجيفاواي', type: 'text', placeholder: '🎉' },
          { key: 'winner_message_style', label: 'شكل رسالة الفائزين', type: 'select', options: [['embed', 'Embed'], ['plain', 'عادية']] },
        ],
      },
    };
    const COMMAND_NAME_OVERRIDES = {
      'م': 'clear',
      'ر': 'return',
      'ØªØ­Ø°ÙŠØ±': 'warn',
      'Ã˜ÂªÃ˜Â­Ã˜Â°Ã™Å Ã˜Â±': 'warn',
      'warn_ar': 'warn',
      'Ø§Ù†ØªØ­Ø°ÙŠØ±': 'unwarn',
      'Ã˜Â§Ã™â€ Ã˜ÂªÃ˜Â­Ã˜Â°Ã™Å Ã˜Â±': 'unwarn',
      'unwarn_ar': 'unwarn',
      'ØªØ­Ø°ÙŠØ±Ø§Øª': 'warnings',
      'Ã˜ÂªÃ˜Â­Ã˜Â°Ã™Å Ã˜Â±Ã˜Â§Ã˜Âª': 'warnings',
      'warnings_ar': 'warnings',
      'Ù‚ÙÙ„': 'lock',
      'Ã™â€šÃ™ÂÃ™â€ž': 'lock',
      'lock_ar': 'lock',
      'ÙØªØ­': 'unlock',
      'Ã™ÂÃ˜ÂªÃ˜Â­': 'unlock',
      'unlock_ar': 'unlock'
    };
    const STATIC_COMMAND_KEYS = ['t', 'r', 'giveaway', 'ban', 'time', 'kick', 'warn', 'unban', 'untime', 'unwarn', 'warnings'];
    function supportsReplyTargetSetting(name){
      const normalized = normalizeCommandName(name);
      if (['ban', 'time', 'kick', 'warn', 'unban', 'untime', 'unwarn', 'warnings'].includes(normalized)) return true;
      const raw = String(name || '').trim().toLowerCase();
      return raw === '\u062a\u062d\u0630\u064a\u0631'
        || raw === '\u0627\u0646\u062a\u062d\u0630\u064a\u0631'
        || raw === '\u062a\u062d\u0630\u064a\u0631\u0627\u062a'
        || raw.includes('warn');
    }
    function normalizeCommandName(name){
      const key = String(name || '').trim().toLowerCase();
      return COMMAND_NAME_OVERRIDES[key] || key;
    }
    function getCommandSettingsMap(){
      const raw = currentSettings?.command_settings_json;
      if (!raw) return {};
      if (typeof raw === 'object' && !Array.isArray(raw)) return raw;
      try {
        const parsed = JSON.parse(String(raw || '{}'));
        return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
      } catch (_) {
        return {};
      }
    }
    function setCommandSettingsMap(map){
      currentSettings.command_settings_json = map && typeof map === 'object' ? map : {};
    }
    function getSavedCommandConfig(commandKey){
      const all = getCommandSettingsMap();
      const key = normalizeCommandName(commandKey);
      const value = all[key];
      return value && typeof value === 'object' ? value : {};
    }
    function getCommandCardKeys(){
      const dynamic = Array.isArray(availableCommands)
        ? availableCommands.map(name => normalizeCommandName(name)).filter(Boolean)
        : [];
      const merged = Array.from(new Set([...STATIC_COMMAND_KEYS, ...dynamic, ...Object.keys(COMMAND_CONFIGS)]));
      return merged.sort((a, b) => a.localeCompare(b));
    }
    function getCommandConfig(commandKey){
      const key = normalizeCommandName(commandKey);
      const genericFields = [
        { key: 'require_prefix', label: 'يتطلب بريفكس', type: 'select', options: [['0', 'لا'], ['1', 'نعم']] },
        { key: 'channel_mode', label: 'مكان عمل الأمر', type: 'select', options: [['any', 'أي روم'], ['selected', 'رومات معينة فقط']] },
        { key: 'channel_ids', label: 'الرومات المسموحة', type: 'channels' },
      ];
      if (COMMAND_CONFIGS[key]) {
        const extraFields = supportsReplyTargetSetting(commandKey)
          ? [{ key: 'allow_reply_target', label: 'استبدال المنشن بـ reply', type: 'select', options: [['0', 'لا'], ['1', 'نعم']] }]
          : [];
        return {
          ...COMMAND_CONFIGS[key],
          key,
          fields: [
            ...genericFields,
            ...extraFields,
            ...COMMAND_CONFIGS[key].fields.filter(field => !['command_t_require_prefix','command_r_require_prefix','command_t_channel_mode','command_r_channel_mode','command_t_channel_ids','command_r_channel_ids'].includes(field.key)),
          ],
        };
      }
      return {
        key,
        title: 'أمر ' + key,
        sub: 'إعدادات عامة للأمر داخل هذا السيرفر.',
        enabledKey: '',
        fields: [
          ...genericFields,
          ...(supportsReplyTargetSetting(commandKey)
            ? [{ key: 'allow_reply_target', label: 'استبدال المنشن بـ reply', type: 'select', options: [['0', 'لا'], ['1', 'نعم']] }]
            : []),
        ],
      };
    }
    function status(t,e){q('status').textContent=t;q('status').style.color=e?'#fca5a5':'#94a3b8';}
    function openReplyEditor(){
      const modal = q('replyModal');
      if (!modal) return;
      modal.classList.add('show');
      modal.setAttribute('aria-hidden', 'false');
      document.body.classList.add('auth-locked');
    }
    function closeReplyEditor(){
      const modal = q('replyModal');
      if (!modal) return;
      modal.classList.remove('show');
      modal.setAttribute('aria-hidden', 'true');
      document.body.classList.remove('auth-locked');
    }
    function collectReplyResponses(){
      const wrap = q('reply_responses_wrap');
      if (!wrap) return [];
      return Array.from(wrap.querySelectorAll('textarea[data-reply-response]'))
        .map(x => String(x.value || '').trim())
        .filter(Boolean);
    }
    function addReplyResponseInput(value=''){
      const wrap = q('reply_responses_wrap');
      if (!wrap) return;
      const item = document.createElement('div');
      item.className = 'reply-response-item';

      const head = document.createElement('div');
      head.className = 'reply-response-head';
      const title = document.createElement('span');
      title.textContent = 'رد';
      const removeBtn = document.createElement('button');
      removeBtn.type = 'button';
      removeBtn.textContent = 'حذف';
      removeBtn.className = 'reply-response-remove';
      removeBtn.onclick = () => {
        const all = wrap.querySelectorAll('.reply-response-item');
        if (all.length <= 1) {
          const area = item.querySelector('textarea[data-reply-response]');
          if (area) area.value = '';
          return;
        }
        item.remove();
        refreshReplyResponseIndexes();
      };
      head.append(title, removeBtn);

      const area = document.createElement('textarea');
      area.setAttribute('data-reply-response', '1');
      area.value = value || '';
      area.placeholder = 'اكتب نص الرد هنا...';

      item.append(head, area);
      wrap.appendChild(item);
      refreshReplyResponseIndexes();
    }
    function refreshReplyResponseIndexes(){
      const wrap = q('reply_responses_wrap');
      if (!wrap) return;
      Array.from(wrap.querySelectorAll('.reply-response-item')).forEach((item, index) => {
        const label = item.querySelector('.reply-response-head span');
        if (label) label.textContent = 'رد #' + (index + 1);
      });
    }
    function renderReplyResponses(values){
      const wrap = q('reply_responses_wrap');
      if (!wrap) return;
      wrap.innerHTML = '';
      const arr = Array.isArray(values) ? values.map(v => String(v || '').trim()).filter(Boolean) : [];
      if (!arr.length) {
        addReplyResponseInput('');
        return;
      }
      arr.forEach(v => addReplyResponseInput(v));
    }
    function selectedValues(el){
      if (!el) return [];
      if (el.tagName === 'SELECT') {
        return Array.from(el.selectedOptions || []).map(o => o.value);
      }
      return Array.from(el.querySelectorAll('input[type="checkbox"]:checked'))
        .map(input => input.getAttribute('data-role-id') || input.getAttribute('data-channel-id'))
        .filter(Boolean);
    }
    function parseCsvValues(value){
      return String(value || '').split(',').map(v => v.trim()).filter(Boolean);
    }
    function createSearchControl(placeholder, onInput, inputAttrs = {}) {
      const wrap = document.createElement('div');
      wrap.className = 'search-control';
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'search-toggle-btn';
      btn.setAttribute('aria-label', 'بحث');
      btn.title = 'بحث';
      btn.textContent = 'بحث';
      const input = document.createElement('input');
      input.type = 'text';
      input.className = 'search-pop';
      input.placeholder = placeholder || 'ابحث...';
      Object.entries(inputAttrs || {}).forEach(([key, value]) => input.setAttribute(key, value));
      btn.onclick = () => {
        wrap.classList.toggle('open');
        if (wrap.classList.contains('open')) {
          setTimeout(() => input.focus(), 0);
        } else {
          input.value = '';
          if (typeof onInput === 'function') onInput('');
        }
      };
      input.oninput = () => {
        if (typeof onInput === 'function') onInput(input.value || '');
      };
      wrap.append(btn, input);
      return { wrap, input, button: btn };
    }
    function ensureChecklistSearch(container, placeholder){
      if (!container) return;
      let wrap = container.previousElementSibling;
      let input = wrap?.querySelector?.('.search-pop');
      if (!wrap || !wrap.classList || !wrap.classList.contains('search-control') || !input) {
        const control = createSearchControl(placeholder, (rawTerm) => {
          const term = String(rawTerm || '').trim().toLowerCase();
          Array.from(container.children).forEach((child) => {
            const text = String(child.textContent || '').toLowerCase();
            child.style.display = !term || text.includes(term) ? '' : 'none';
          });
        });
        wrap = control.wrap;
        input = control.input;
        container.parentNode.insertBefore(wrap, container);
      } else {
        input.placeholder = placeholder || 'ابحث...';
      }
      if (input.value) input.oninput();
    }
    function escapeHtml(value){
      return String(value || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }
    function updateReplyReplyOptions(){
      const wrap = q('replyPingingWrap');
      const isReply = !!q('reply_send_as_reply')?.checked;
      if (wrap) wrap.style.display = isReply ? '' : 'none';
      if (!isReply && q('reply_pinging')) q('reply_pinging').checked = false;
    }
    function buildChannelOptionsHtml(selectedValue, filterText=''){
      const term = String(filterText || '').trim().toLowerCase();
      const options = ['<option value="">اختر قناة</option>'];
      guildChannels.forEach(channel => {
        if (term && !String(channel.name || '').toLowerCase().includes(term) && !String(channel.id || '').includes(term)) return;
        const selected = String(selectedValue || '') === String(channel.id) ? ' selected' : '';
        options.push('<option value="'+channel.id+'"'+selected+'>#'+channel.name+'</option>');
      });
      return options.join('');
    }
    function createChannelSelectElement(id, value='', withId=true){
      const select = document.createElement('select');
      if (withId) select.id = id;
      select.setAttribute('data-setting-input', id);
      select.innerHTML = buildChannelOptionsHtml(value);
      return select;
    }
    function getFieldValues(id){
      if (!CHANNEL_FIELD_IDS.includes(id)) {
        return [q(id)?.value?.trim() || ''].filter(Boolean);
      }
      const list = document.querySelector('[data-setting-list="'+id+'"]');
      if (!list) return [q(id)?.value?.trim() || ''].filter(Boolean);
      return Array.from(list.querySelectorAll('[data-setting-input="'+id+'"]'))
        .map(input => String(input.value || '').trim())
        .filter(Boolean);
    }
    function createChannelInputRow(id, value=''){
      const row = document.createElement('div');
      row.className = 'multi-input-row';
      row.appendChild(createChannelSelectElement(id, value, false));
      const removeBtn = createChannelRemoveButton(id, row);
      row.appendChild(removeBtn);
      return row;
    }
    function createChannelRemoveButton(id, row){
      const removeBtn = document.createElement('button');
      removeBtn.type = 'button';
      removeBtn.className = 'mini-btn';
      removeBtn.textContent = 'حذف';
      removeBtn.onclick = () => {
        const list = row.parentElement;
        if (list && list.querySelectorAll('.multi-input-row').length > 1) row.remove();
        else {
          const select = row.querySelector('select[data-setting-input="'+id+'"]');
          if (select) select.value = '';
        }
      };
      return removeBtn;
    }
    function refreshChannelFieldOptions(id){
      const filter = document.querySelector('[data-setting-search="'+id+'"]')?.value || '';
      document.querySelectorAll('select[data-setting-input="'+id+'"]').forEach(select => {
        const selected = select.value;
        select.innerHTML = buildChannelOptionsHtml(selected, filter);
      });
    }
    function setFieldValues(id, rawValue){
      const values = parseCsvValues(rawValue);
      if (!CHANNEL_FIELD_IDS.includes(id)) {
        const input = q(id);
        if (input) input.value = String(rawValue ?? '');
        return;
      }
      const list = document.querySelector('[data-setting-list="'+id+'"]');
      if (!list) {
        const input = q(id);
        if (input) input.value = values[0] || '';
        return;
      }
      list.innerHTML = '';
      const items = values.length ? values : [''];
      items.forEach((value, index) => {
        if (index === 0) {
          const searchControl = createSearchControl('ابحث عن قناة...', () => refreshChannelFieldOptions(id), { 'data-setting-search': id });
          const firstRow = document.createElement('div');
          firstRow.className = 'multi-input-row inline-select-search';
          firstRow.appendChild(createChannelSelectElement(id, value, true));
          firstRow.appendChild(searchControl.wrap);
          firstRow.appendChild(createChannelRemoveButton(id, firstRow));
          list.appendChild(firstRow);
        } else {
          list.appendChild(createChannelInputRow(id, value));
        }
      });
      refreshChannelFieldOptions(id);
    }
    function initSettingsLayout(){
      const firstField = q('welcome_channel_id');
      if(!firstField) return;
      const card = firstField.closest('.c');
      if(!card || card.querySelector('.settings-grid')) return;

      const headNotes = Array.from(card.querySelectorAll(':scope > .m'));
      headNotes.forEach(note => note.classList.add('settings-head-note'));
      const oldRows = Array.from(card.querySelectorAll(':scope > .r'));
      oldRows.forEach(row => { row.style.display = 'none'; });

      const grid = document.createElement('div');
      grid.className = 'settings-grid';

      for (const [id, labelText] of SETTINGS_FIELDS) {
        const input = q(id);
        if (!input) continue;
        input.placeholder = '';
        const wrap = document.createElement('div');
        wrap.className = 'settings-field';
        const label = document.createElement('label');
        label.setAttribute('for', id);
        label.textContent = labelText;
        wrap.append(label);
        if (CHANNEL_FIELD_IDS.includes(id)) {
          const list = document.createElement('div');
          list.className = 'multi-input-list';
          list.setAttribute('data-setting-list', id);
          const searchControl = createSearchControl('ابحث عن قناة...', () => refreshChannelFieldOptions(id), { 'data-setting-search': id });
          const firstRow = document.createElement('div');
          firstRow.className = 'multi-input-row inline-select-search';
          firstRow.appendChild(createChannelSelectElement(id, '', true));
          firstRow.appendChild(searchControl.wrap);
          firstRow.appendChild(createChannelRemoveButton(id, firstRow));
          list.appendChild(firstRow);
          const addBtn = document.createElement('button');
          addBtn.type = 'button';
          addBtn.className = 'mini-btn add-channel-btn';
          addBtn.textContent = '+ إضافة قناة';
          addBtn.onclick = () => {
            list.appendChild(createChannelInputRow(id, ''));
            refreshChannelFieldOptions(id);
          };
          wrap.append(list, addBtn);
        } else {
          wrap.append(input);
        }
        grid.appendChild(wrap);
      }

      const saveBtn = q('saveSettings');
      if (saveBtn) {
        const action = document.createElement('div');
        action.className = 'settings-actions';
        action.appendChild(saveBtn);
        grid.appendChild(action);
      }

      card.appendChild(grid);
    }
    function withToken(path) {
      const u = new URL(path, location.origin);
      if (token) u.searchParams.set('token', token);
      return u.toString();
    }
    async function api(path, options = {}) {
      const u = new URL(path, location.origin); if(token) u.searchParams.set('token', token);
      const r = await fetch(u.toString(), { ...options, headers: { 'Content-Type': 'application/json', ...(options.headers||{}) } });
      if(!r.ok){ throw new Error(await r.text() || ('HTTP '+r.status)); }
      const ct = r.headers.get('content-type') || ''; return ct.includes('application/json') ? r.json() : r.text();
    }
    async function fetchAuthStatus(){
      const r = await fetch(withToken('/auth/me'), { headers: { 'Accept': 'application/json' } });
      const ct = r.headers.get('content-type') || '';
      let data = null;
      try {
        data = ct.includes('application/json') ? await r.json() : { error: await r.text() };
      } catch (_) {
        data = { error: 'failed_to_parse_auth_response' };
      }
      return { ok: r.ok, status: r.status, data };
    }
    function renderAuthSummary(){
      const box = q('authSummary');
      if (!box) return;
      if (!authUser) {
        box.textContent = 'غير مسجل الدخول';
        return;
      }
      const label = authUser.global_name || authUser.username || authUser.id;
      box.textContent = 'مسجل الدخول: ' + label;
    }
    function showAuthModal(message){
      document.body.classList.add('auth-locked');
      q('authOverlay').classList.add('show');
      q('authErr').style.display = message ? 'block' : 'none';
      q('authErr').textContent = message || '';
      q('authSubmit').onclick = () => { location.href = withToken('/auth/discord'); };
    }
    function hideAuthModal(){
      q('authOverlay').classList.remove('show');
      document.body.classList.remove('auth-locked');
    }
    async function ensureDashboardSession(){
      const auth = await fetchAuthStatus().catch(() => ({ ok: false, status: 500, data: { error: 'network_error' } }));
      if (auth.ok && auth.data && auth.data.user) {
        authUser = auth.data.user;
        renderAuthSummary();
        hideAuthModal();
        return true;
      }
      authUser = null;
      renderAuthSummary();
      let message = '';
      if (auth.status === 503) {
        message = 'إعدادات Discord OAuth2 غير مكتملة. أكمل CLIENT_ID و CLIENT_SECRET و REDIRECT_URI أولاً.';
      } else if (authError) {
        message = 'فشل تسجيل الدخول: ' + authError;
      }
      showAuthModal(message);
      return false;
    }
    function fillSettings(s){
      currentSettings = Object.assign({}, s || {});
      try {
        currentSettings.command_settings_json = typeof currentSettings.command_settings_json === 'object'
          ? (currentSettings.command_settings_json || {})
          : JSON.parse(String(currentSettings.command_settings_json || '{}'));
      } catch (_) {
        currentSettings.command_settings_json = {};
      }
      const keys=['welcome_channel_id','goodbye_channel_id','levelup_channel_id','muted_role_id','ticket_category_id','log_roles_channel_id','log_rooms_channel_id','log_bans_channel_id','log_time_channel_id','log_kick_channel_id','log_message_edit_channel_id','log_message_delete_channel_id','stats_enabled','auto_reply_delete_trigger','automod_spam_enabled','automod_links_enabled','automod_caps_enabled','automod_warn_threshold','custom_prefix'];
      for (const k of keys){ setFieldValues(k, s[k] ?? (k.includes('enabled')?'0':'')); }
      renderCommandCards();
    }
    function fillMessages(m){ for (const k of MSG_KEYS){ q('msg_'+k).value = m[k] || ''; } }
    function drawRoles(roles){
      roleNameById.clear();
      for (const role of roles) roleNameById.set(role.id, role.name);
      q('roles').innerHTML = roles.length ? roles.map(r=>'<tr><td>'+r.name+'</td><td><code>'+r.id+'</code></td><td>'+r.position+'</td></tr>').join('') : '<tr><td colspan="3" class="m">لا توجد رتب</td></tr>';
      q('rolesCount').textContent = roles.length ? ('إجمالي الرتب: ' + roles.length) : 'لا توجد رتب';
      const roleChecks = roles.length
        ? roles.map(r =>
            '<label class="role-check"><input type="checkbox" data-role-id="'+r.id+'" />' +
            '<span>'+r.name+'</span><span class="rid">('+r.id+')</span></label>'
          ).join('')
        : '<div class="m">لا توجد رتب.</div>';
      q('reply_roles').innerHTML = roleChecks;
      q('reply_roles_disabled').innerHTML = roleChecks;
      ensureChecklistSearch(q('reply_roles'), 'ابحث عن رتبة مفعلة...');
      ensureChecklistSearch(q('reply_roles_disabled'), 'ابحث عن رتبة معطلة...');
      q('role_level_role').innerHTML = '<option value="">اختر رتبة</option>' + roles.map(r=>'<option value="'+r.id+'">'+r.name+' ('+r.id+')</option>').join('');
    }
    function drawChannels(channels){
      guildChannels = Array.isArray(channels) ? channels.slice() : [];
      channelNameById.clear();
      for (const channel of channels) channelNameById.set(channel.id, channel.name);
      q('reply_channels').innerHTML = channels.length
          ? channels.map(ch =>
              '<label class="channel-card">' +
              '<span class="channel-meta"><span class="channel-name">#'+escapeHtml(ch.name || 'unknown-channel')+'</span><span class="channel-sub">'+ch.id+'</span></span>' +
              '<input class="channel-toggle" type="checkbox" data-channel-id="'+ch.id+'" /></label>'
            ).join('')
          : '<div class="m">لا توجد رومات نصية.</div>';
      q('reply_channels').classList.add('channel-checklist');
      ensureChecklistSearch(q('reply_channels'), 'ابحث عن روم...');
      document.querySelectorAll('select[data-setting-input]').forEach(select => {
        const selected = select.value;
        const id = select.getAttribute('data-setting-input');
        const filter = id ? (document.querySelector('[data-setting-search="'+id+'"]')?.value || '') : '';
        select.innerHTML = buildChannelOptionsHtml(selected, filter);
      });
    }
    function drawBlacklist(words){
      q('blackListBox').innerHTML = words.length
        ? words.map(w=>'<span style="margin-right:8px;">'+w+' <button data-word="'+encodeURIComponent(w)+'">x</button></span>').join('')
        : '<span class="m">لا توجد كلمات</span>';
      Array.from(q('blackListBox').querySelectorAll('button[data-word]')).forEach(btn => {
        btn.onclick = () => removeBlack(decodeURIComponent(btn.getAttribute('data-word')));
      });
    }
    function drawRoleLevels(items){
      q('roleLevelsBox').innerHTML = items.length
        ? items.map(it=>'<span style="margin-right:8px;">مستوى '+it.level+' -> '+(roleNameById.get(it.role_id)||it.role_id)+' <button data-lv="'+it.level+'">x</button></span>').join('')
        : '<span class="m">لا توجد إعدادات</span>';
      Array.from(q('roleLevelsBox').querySelectorAll('button[data-lv]')).forEach(btn => {
        btn.onclick = () => removeRoleLevel(btn.getAttribute('data-lv'));
      });
    }
    function drawCredits(items){
      q('creditRows').innerHTML = items.length
        ? items.map((it, idx)=>'<tr><td>'+(idx+1)+'</td><td>'+(it.display_name||it.user_id)+'</td><td>'+it.balance+'</td></tr>').join('')
        : '<tr><td colspan="3" class="m">لا توجد بيانات</td></tr>';
    }
    function fillCommandList(commands){
      availableCommands = Array.isArray(commands) ? commands.slice() : [];
      q('alias_command').innerHTML = availableCommands.length
        ? availableCommands.map(name => '<option value="'+name+'">'+name+'</option>').join('')
        : '<option value="">لا توجد أوامر</option>';
      renderCommandCards();
    }
    function drawCommandAliases(items){
      q('aliasRows').innerHTML = items.length
        ? items.map(it => '<tr><td><code>'+it.command_name+'</code></td><td><code>'+it.alias_name+'</code></td><td><button data-del-alias="'+it.id+'">حذف</button></td></tr>').join('')
        : '<tr><td colspan="3" class="m">لا توجد كلمات مضافة</td></tr>';
      Array.from(q('aliasRows').querySelectorAll('button[data-del-alias]')).forEach(btn => {
        btn.onclick = () => deleteCommandAlias(btn.getAttribute('data-del-alias'));
      });
    }
    function renderCommandCards(){
      const box = q('commandCards');
      if (!box) return;
      const term = String(q('commandSearch')?.value || '').trim().toLowerCase();
      const keys = getCommandCardKeys().filter((key) => {
        if (!term) return true;
        const config = getCommandConfig(key);
        return key.includes(term)
          || String(config.title || '').toLowerCase().includes(term)
          || String(config.sub || '').toLowerCase().includes(term);
      });
      box.innerHTML = keys.map((key) => {
        const config = getCommandConfig(key);
        const saved = getSavedCommandConfig(key);
        const hasRealToggle = !!config.enabledKey || true;
        const enabled = config.enabledKey
          ? Number(currentSettings[config.enabledKey] ?? saved.enabled ?? 1) !== 0
          : Number(saved.enabled ?? 1) !== 0;
        const toggleLabel = enabled ? 'مفعل' : 'معطل';
        return '<div class="command-card" data-command-open="'+key+'">'
          + '<div class="command-card-head"><div><div class="command-card-title">'+config.title+'</div><div class="command-card-sub">'+config.sub+'</div></div>'
          + '<label class="toggle-chip"><input type="checkbox" data-command-toggle="'+key+'" '+(enabled?'checked':'')+' /> '+toggleLabel+'</label></div>'
          + '<div class="command-card-actions"><button type="button" data-command-open="'+key+'">فتح الإعدادات</button></div>'
          + '</div>';
      }).join('');

      if (!keys.length) {
        box.innerHTML = '<div class="m">لا توجد أوامر مطابقة للبحث.</div>';
      }

      Array.from(box.querySelectorAll('[data-command-toggle]')).forEach(input => {
        input.onchange = (ev) => {
          ev.stopPropagation();
          saveCommandToggle(input.getAttribute('data-command-toggle'), input.checked ? 1 : 0);
        };
        input.onclick = ev => ev.stopPropagation();
      });
      Array.from(box.querySelectorAll('[data-command-open]')).forEach(btn => {
        btn.onclick = (ev) => {
          ev.stopPropagation();
          openCommandModal(btn.getAttribute('data-command-open'));
        };
      });
    }
    function openCommandModal(commandKey){
      const config = getCommandConfig(commandKey);
      if (!config) return;
      editingCommandKey = commandKey;
      q('commandModalTitle').textContent = config.title;
      const body = q('commandModalBody');
      body.innerHTML = '';
      const saved = getSavedCommandConfig(commandKey);
      q('saveCommandConfig').style.display = '';
      config.fields.forEach(field => {
        const wrap = document.createElement('div');
        wrap.className = 'settings-field';
        wrap.setAttribute('data-command-field', field.key);
        const label = document.createElement('label');
        label.textContent = field.label;
        wrap.append(label);
        if (field.type === 'channels') {
          let box;
          const searchControl = createSearchControl('ابحث عن روم...', (rawTerm) => {
            const term = String(rawTerm || '').trim().toLowerCase();
            Array.from(box.children).forEach((child) => {
              const text = String(child.textContent || '').toLowerCase();
              child.style.display = !term || text.includes(term) ? '' : 'none';
            });
          });
          wrap.append(searchControl.wrap);

          box = document.createElement('div');
          box.id = 'cmdcfg_' + field.key;
          box.className = 'roles-checklist channel-checklist';
          const selectedSource = field.key === 'channel_ids'
            ? String(saved.channel_ids || '')
            : String(currentSettings[field.key] || '');
          const selected = new Set(parseCsvValues(selectedSource));
          box.innerHTML = guildChannels.length
            ? guildChannels.map(ch =>
                '<label class="channel-card">'
                + '<span class="channel-meta"><span class="channel-name">#'+escapeHtml(ch.name || 'unknown-channel')+'</span><span class="channel-sub">'+ch.id+'</span></span>'
                + '<input class="channel-toggle" type="checkbox" data-channel-id="'+ch.id+'" '+(selected.has(ch.id)?'checked':'')+' /></label>'
              ).join('')
              : '<div class="m">لا توجد رومات.</div>';
          wrap.append(box);
        } else if (field.type === 'text') {
          const input = document.createElement('input');
          input.type = 'text';
          input.id = 'cmdcfg_' + field.key;
          input.placeholder = field.placeholder || '';
          const currentValue = String(currentSettings[field.key] ?? saved[field.key] ?? '');
          input.value = currentValue;
          wrap.append(input);
        } else {
          const select = document.createElement('select');
          select.id = 'cmdcfg_' + field.key;
          field.options.forEach(([value, text]) => {
            const option = document.createElement('option');
            option.value = value;
            option.textContent = text;
            select.appendChild(option);
          });
          const currentValue = field.key === 'require_prefix'
            ? String(saved.require_prefix ?? (config.key === 't' ? currentSettings.command_t_require_prefix : config.key === 'r' ? currentSettings.command_r_require_prefix : field.options[0][0]) ?? field.options[0][0])
            : field.key === 'channel_mode'
              ? String(saved.channel_mode ?? (config.key === 't' ? currentSettings.command_t_channel_mode : config.key === 'r' ? currentSettings.command_r_channel_mode : field.options[0][0]) ?? field.options[0][0])
              : field.key === 'allow_reply_target'
                ? String(saved.allow_reply_target ?? field.options[0][0])
              : String(currentSettings[field.key] || field.options[0][0]);
          select.value = currentValue;
          wrap.append(select);
        }
        body.appendChild(wrap);
      });
      const channelModeKey = config.fields.some(field => field.key === 'channel_mode')
        ? 'channel_mode'
        : 'command_' + commandKey + '_channel_mode';
      const channelModeInput = q('cmdcfg_' + channelModeKey);
      if (channelModeInput) {
        const syncChannelVisibility = () => {
          const wrap = body.querySelector('[data-command-field="channel_ids"]') || body.querySelector('[data-command-field="command_'+commandKey+'_channel_ids"]');
          if (wrap) wrap.style.display = channelModeInput.value === 'selected' ? '' : 'none';
        };
        channelModeInput.onchange = syncChannelVisibility;
        syncChannelVisibility();
      }
      q('commandModal').classList.add('show');
      q('commandModal').setAttribute('aria-hidden', 'false');
      document.body.classList.add('auth-locked');
    }
    function closeCommandModal(){
      editingCommandKey = null;
      q('commandModal').classList.remove('show');
      q('commandModal').setAttribute('aria-hidden', 'true');
      document.body.classList.remove('auth-locked');
    }
    async function saveCommandToggle(commandKey, enabled){
      const config = getCommandConfig(commandKey);
      if (!config || !guildId) return;
      const map = getCommandSettingsMap();
      const key = normalizeCommandName(commandKey);
      map[key] = { ...(map[key] || {}), enabled };
      setCommandSettingsMap(map);
      const payload = { command_settings_json: map };
      if (config.enabledKey) {
        currentSettings[config.enabledKey] = enabled;
        payload[config.enabledKey] = enabled;
      }
      await api('/api/guilds/'+guildId+'/settings',{method:'PUT',body:JSON.stringify(payload)});
      renderCommandCards();
      status('تم حفظ حالة الأمر');
    }
    async function saveCommandConfig(){
      const config = getCommandConfig(editingCommandKey);
      if (!config || !guildId) return;
      const payload = {};
      const map = getCommandSettingsMap();
      const key = normalizeCommandName(editingCommandKey);
      const saved = { ...(map[key] || {}) };
      config.fields.forEach(field => {
        if (field.type === 'channels') {
          const value = selectedValues(q('cmdcfg_' + field.key)).join(',');
          if (field.key === 'channel_ids') saved.channel_ids = value;
          else payload[field.key] = value;
        } else if (field.type === 'text') {
          const value = String(q('cmdcfg_' + field.key)?.value || '').trim();
          payload[field.key] = value;
        } else {
          const value = q('cmdcfg_' + field.key)?.value || field.options[0][0];
          if (field.key === 'require_prefix') saved.require_prefix = Number(value);
          else if (field.key === 'channel_mode') saved.channel_mode = String(value);
          else if (field.key === 'allow_reply_target') saved.allow_reply_target = Number(value);
          else payload[field.key] = value;
        }
        if (Object.prototype.hasOwnProperty.call(payload, field.key)) currentSettings[field.key] = payload[field.key];
      });
      map[key] = saved;
      setCommandSettingsMap(map);
      payload.command_settings_json = map;
      if (key === 't') {
        currentSettings.command_t_require_prefix = saved.require_prefix ?? 0;
        currentSettings.command_t_channel_mode = saved.channel_mode || 'any';
        currentSettings.command_t_channel_ids = saved.channel_ids || '';
        payload.command_t_require_prefix = currentSettings.command_t_require_prefix;
        payload.command_t_channel_mode = currentSettings.command_t_channel_mode;
        payload.command_t_channel_ids = currentSettings.command_t_channel_ids;
      } else if (key === 'r') {
        currentSettings.command_r_require_prefix = saved.require_prefix ?? 0;
        currentSettings.command_r_channel_mode = saved.channel_mode || 'any';
        currentSettings.command_r_channel_ids = saved.channel_ids || '';
        payload.command_r_require_prefix = currentSettings.command_r_require_prefix;
        payload.command_r_channel_mode = currentSettings.command_r_channel_mode;
        payload.command_r_channel_ids = currentSettings.command_r_channel_ids;
      }
      await api('/api/guilds/'+guildId+'/settings',{method:'PUT',body:JSON.stringify(payload)});
      renderCommandCards();
      closeCommandModal();
      status('تم حفظ إعدادات الأمر');
    }
    async function savePrefixConfig(){
      if (!guildId) return;
      const custom_prefix = String(q('custom_prefix')?.value || '').trim();
      currentSettings.custom_prefix = custom_prefix;
      await api('/api/guilds/'+guildId+'/settings',{method:'PUT',body:JSON.stringify({custom_prefix})});
      status(custom_prefix ? 'تم حفظ البريفكس' : 'تم إلغاء البريفكس العام');
    }
    function resetReplyForm(){
      editingReplyId=null;
      q('reply_trigger').value='';
      q('reply_enabled').checked=true;
      q('reply_send_as_reply').checked=true;
      q('reply_pinging').checked=false;
      q('reply_delete_trigger').checked=false;
      q('reply_contains').checked=false;
      q('reply_match_mode').value='exact';
      renderReplyResponses([]);
      Array.from(q('reply_roles').querySelectorAll('input[type="checkbox"][data-role-id]')).forEach(input => { input.checked = false; });
      Array.from(q('reply_roles_disabled').querySelectorAll('input[type="checkbox"][data-role-id]')).forEach(input => { input.checked = false; });
      Array.from(q('reply_channels').querySelectorAll('input[type="checkbox"][data-channel-id]')).forEach(input => { input.checked = false; });
      q('editState').textContent='الوضع الحالي: إنشاء رد جديد';
      if (q('replyModalTitle')) q('replyModalTitle').textContent='إضافة رد تلقائي';
      updateReplyReplyOptions();
    }
    function editReply(item){
      editingReplyId=item.id;
      q('reply_trigger').value=item.trigger||'';
      q('reply_enabled').checked=!!item.enabled;
      q('reply_send_as_reply').checked=Number(item.send_as_reply ?? 1) === 1;
      q('reply_pinging').checked=!!item.pinging;
      q('reply_delete_trigger').checked=!!item.delete_trigger_message;
      const mode=(item.match_mode||'exact');
      q('reply_match_mode').value=mode;
      q('reply_contains').checked=(mode==='contains');
      renderReplyResponses(Array.isArray(item.responses)?item.responses:(item.response?[item.response]:[]));
      const set = new Set(Array.isArray(item.allowed_role_ids)?item.allowed_role_ids:[]);
      const disabledSet = new Set(Array.isArray(item.disabled_role_ids)?item.disabled_role_ids:[]);
      const blockedChannels = new Set(Array.isArray(item.excluded_channel_ids)?item.excluded_channel_ids:[]);
      Array.from(q('reply_roles').querySelectorAll('input[type="checkbox"][data-role-id]')).forEach(input => {
        input.checked = set.has(input.getAttribute('data-role-id'));
      });
      Array.from(q('reply_roles_disabled').querySelectorAll('input[type="checkbox"][data-role-id]')).forEach(input => {
        input.checked = disabledSet.has(input.getAttribute('data-role-id'));
      });
      Array.from(q('reply_channels').querySelectorAll('input[type="checkbox"][data-channel-id]')).forEach(input => {
        input.checked = blockedChannels.has(input.getAttribute('data-channel-id'));
      });
      q('editState').textContent='الوضع الحالي: تعديل الرد #' + item.id;
      if (q('replyModalTitle')) q('replyModalTitle').textContent='تعديل رد تلقائي';
      updateReplyReplyOptions();
      openReplyEditor();
    }
    function drawReplies(items){
      const b=q('replies');
      b.innerHTML='';
      if(!items.length){
        b.innerHTML='<tr><td colspan="2" class="m">لا توجد ردود</td></tr>';
        return;
      }
      for(const it of items){
        const tr=document.createElement('tr');
        tr.innerHTML='<td><b>'+it.trigger+'</b></td><td><button data-e="1">تعديل</button> <button data-t="1">تفعيل/تعطيل</button> <button data-d="1">حذف</button></td>';
        tr.querySelector('[data-e]').onclick=()=>editReply(it);
        tr.querySelector('[data-t]').onclick=()=>toggleReply(it.id, it.enabled ? 0 : 1);
        tr.querySelector('[data-d]').onclick=()=>deleteReply(it.id);
        b.appendChild(tr);
      }
    }
    async function loadGuilds(){
      status('جاري تحميل السيرفرات...'); const d=await api('/api/guilds'); const sel=q('guild'); sel.innerHTML='';
      for(const g of (d.guilds||[])){ const op=document.createElement('option'); op.value=g.id; op.textContent=g.name+' ('+g.members+')'; sel.appendChild(op); }
      if(!sel.value){ status('لا توجد سيرفرات متاحة لهذا الحساب. تأكد أنك داخل السيرفر وأن لديك صلاحية الإدارة.', true); return; } sel.onchange=()=>loadGuild(sel.value); await loadGuild(sel.value);
    }
    async function loadGuild(id){
      guildId=id;
      status('جاري تحميل بيانات السيرفر...');
      const d=await api('/api/guilds/'+id);
      currentSettings = Object.assign({}, d.settings || {});
      drawChannels(d.channels||[]);
      fillSettings(d.settings||{});
      fillMessages(d.botMessages||{});
      drawRoles(d.roles||[]);
      drawReplies(d.autoReplies||[]);
      drawBlacklist(d.blacklist||[]);
      drawRoleLevels(d.roleLevels||[]);
      fillCommandList(d.commands||[]);
      drawCommandAliases(d.commandAliases||[]);
      resetReplyForm();
      await loadCredits();
      status('تم تحميل السيرفر: '+(d.guild?.name||id));
    }
    async function loadCredits(){ if(!guildId) return; const d = await api('/api/guilds/'+guildId+'/credits?limit=20'); drawCredits(d.items||[]); }
    async function saveSettings(){
      const p={}; for(const k of ['welcome_channel_id','goodbye_channel_id','levelup_channel_id','muted_role_id','ticket_category_id','log_roles_channel_id','log_rooms_channel_id','log_bans_channel_id','log_time_channel_id','log_kick_channel_id','log_message_edit_channel_id','log_message_delete_channel_id']) p[k]=CHANNEL_FIELD_IDS.includes(k)?(getFieldValues(k).join(',')||null):(q(k).value.trim()||null);
      for(const k of ['stats_enabled','auto_reply_delete_trigger','automod_spam_enabled','automod_links_enabled','automod_caps_enabled','automod_warn_threshold']) p[k]=Number(q(k).value||0);
      Object.assign(currentSettings, p);
      await api('/api/guilds/'+guildId+'/settings',{method:'PUT',body:JSON.stringify(p)}); status('تم حفظ الإعدادات');
    }
    async function saveMessages(){ const messages={}; for(const k of MSG_KEYS) messages[k]=q('msg_'+k).value.trim(); await api('/api/guilds/'+guildId+'/bot-messages',{method:'PUT',body:JSON.stringify({messages})}); status('تم حفظ الرسائل'); }
    async function saveReply(){
      const responses = collectReplyResponses();
      const trigger=q('reply_trigger').value.trim();
      const mode = q('reply_contains').checked ? 'contains' : 'exact';
      q('reply_match_mode').value = mode;
      if(!trigger||!responses.length) return;
      const p={
        trigger,
        responses,
        response:responses[0],
        enabled:q('reply_enabled').checked ? 1 : 0,
        send_as_reply:q('reply_send_as_reply').checked ? 1 : 0,
        pinging:q('reply_pinging').checked ? 1 : 0,
        delete_trigger_message:q('reply_delete_trigger').checked ? 1 : 0,
        match_mode:mode,
        allowed_role_ids:selectedValues(q('reply_roles')),
        disabled_role_ids:selectedValues(q('reply_roles_disabled')),
        excluded_channel_ids:selectedValues(q('reply_channels'))
      };
      if(editingReplyId) await api('/api/guilds/'+guildId+'/auto-replies/'+editingReplyId,{method:'PUT',body:JSON.stringify(p)});
      else await api('/api/guilds/'+guildId+'/auto-replies',{method:'POST',body:JSON.stringify(p)});
      const d=await api('/api/guilds/'+guildId+'/auto-replies');
      drawReplies(d.items||[]);
      resetReplyForm();
      closeReplyEditor();
      status('تم حفظ الرد');
    }
    async function toggleReply(id,enabled){ await api('/api/guilds/'+guildId+'/auto-replies/'+id,{method:'PUT',body:JSON.stringify({enabled})}); const d=await api('/api/guilds/'+guildId+'/auto-replies'); drawReplies(d.items||[]); }
    async function deleteReply(id){ await api('/api/guilds/'+guildId+'/auto-replies/'+id,{method:'DELETE'}); const d=await api('/api/guilds/'+guildId+'/auto-replies'); drawReplies(d.items||[]); if(editingReplyId===id){ resetReplyForm(); closeReplyEditor(); } }
    async function addBlack(){
      if(!guildId) return;
      const word = q('black_word').value.trim();
      if(!word) return;
      await api('/api/guilds/'+guildId+'/blacklist',{method:'POST',body:JSON.stringify({word})});
      q('black_word').value='';
      const d=await api('/api/guilds/'+guildId);
      drawBlacklist(d.blacklist||[]);
    }
    async function removeBlack(word){
      if(!guildId) return;
      await api('/api/guilds/'+guildId+'/blacklist/'+encodeURIComponent(word),{method:'DELETE'});
      const d=await api('/api/guilds/'+guildId);
      drawBlacklist(d.blacklist||[]);
    }
    async function setRoleLevelCmd(){
      if(!guildId) return;
      const level = Number(q('role_level_value').value);
      const role_id = q('role_level_role').value.trim();
      if(!level || !role_id) return;
      await api('/api/guilds/'+guildId+'/role-levels',{method:'POST',body:JSON.stringify({level, role_id})});
      q('role_level_value').value='';
      const d=await api('/api/guilds/'+guildId);
      drawRoleLevels(d.roleLevels||[]);
    }
    async function removeRoleLevel(level){
      if(!guildId) return;
      await api('/api/guilds/'+guildId+'/role-levels/'+level,{method:'DELETE'});
      const d=await api('/api/guilds/'+guildId);
      drawRoleLevels(d.roleLevels||[]);
    }
    async function setCredit(){
      if(!guildId) return;
      const user_id = q('credit_user').value.trim();
      const balance = Number(q('credit_amount').value);
      if(!user_id || !Number.isFinite(balance) || balance < 0) return;
      await api('/api/guilds/'+guildId+'/credits/set',{method:'POST',body:JSON.stringify({user_id,balance})});
      await loadCredits();
    }
    async function addCredit(){
      if(!guildId) return;
      const user_id = q('credit_user').value.trim();
      const amount = Number(q('credit_amount').value);
      if(!user_id || !Number.isFinite(amount)) return;
      await api('/api/guilds/'+guildId+'/credits/add',{method:'POST',body:JSON.stringify({user_id,amount})});
      await loadCredits();
    }
    async function loadCommandAliases(){
      if(!guildId) return;
      const d = await api('/api/guilds/'+guildId+'/command-aliases');
      fillCommandList(d.commands||[]);
      drawCommandAliases(d.items||[]);
    }
    async function addCommandAlias(){
      if(!guildId) return;
      const command_name = q('alias_command').value.trim().toLowerCase();
      const alias_name = q('alias_name').value.trim().toLowerCase();
      if(!command_name || !alias_name) return;
      await api('/api/guilds/'+guildId+'/command-aliases',{method:'POST',body:JSON.stringify({command_name,alias_name})});
      q('alias_name').value='';
      await loadCommandAliases();
    }
    async function deleteCommandAlias(id){
      if(!guildId) return;
      await api('/api/guilds/'+guildId+'/command-aliases/'+id,{method:'DELETE'});
      await loadCommandAliases();
    }
    q('saveSettings').onclick=()=>saveSettings().catch(e=>status(e.message,true));
    q('saveMsgs').onclick=()=>saveMessages().catch(e=>status(e.message,true));
    q('saveReply').onclick=()=>saveReply().catch(e=>status(e.message,true));
    q('openReplyModal').onclick=()=>{ resetReplyForm(); openReplyEditor(); };
    q('closeReplyModal').onclick=()=>closeReplyEditor();
    q('replyModal').onclick=(ev)=>{ if(ev.target && ev.target.id==='replyModal') closeReplyEditor(); };
    q('reply_send_as_reply').onchange=()=>updateReplyReplyOptions();
    q('commandModal').onclick=(ev)=>{ if(ev.target && ev.target.id==='commandModal') closeCommandModal(); };
    q('closeCommandModal').onclick=()=>closeCommandModal();
    q('saveCommandConfig').onclick=()=>saveCommandConfig().catch(e=>status(e.message,true));
    q('addReplyResponse').onclick=()=>addReplyResponseInput('');
    q('refreshReplies').onclick=()=>api('/api/guilds/'+guildId+'/auto-replies').then(d=>drawReplies(d.items||[])).catch(e=>status(e.message,true));
    q('clearEdit').onclick=()=>resetReplyForm();
    q('toggleRoles').onclick=()=>{
      const wrap = q('rolesWrap');
      const hidden = wrap.style.display === 'none';
      wrap.style.display = hidden ? '' : 'none';
      q('toggleRoles').textContent = hidden ? 'إخفاء الرتب' : 'إظهار الرتب';
    };
    q('addBlack').onclick=()=>addBlack().catch(e=>status(e.message,true));
    q('setRoleLevel').onclick=()=>setRoleLevelCmd().catch(e=>status(e.message,true));
    q('creditSet').onclick=()=>setCredit().catch(e=>status(e.message,true));
    q('creditAdd').onclick=()=>addCredit().catch(e=>status(e.message,true));
    q('creditRefresh').onclick=()=>loadCredits().catch(e=>status(e.message,true));
    q('savePrefixConfig').onclick=()=>savePrefixConfig().catch(e=>status(e.message,true));
    q('commandSearchToggle').onclick=()=>{
      const wrap = q('commandSearchWrap');
      if (!wrap) return;
      wrap.classList.toggle('open');
      if (wrap.classList.contains('open')) {
        setTimeout(() => q('commandSearch')?.focus(), 0);
      } else if (q('commandSearch')) {
        q('commandSearch').value = '';
        renderCommandCards();
      }
    };
    q('commandSearch').oninput=()=>renderCommandCards();
    q('aliasAdd').onclick=()=>addCommandAlias().catch(e=>status(e.message,true));
    q('aliasRefresh').onclick=()=>loadCommandAliases().catch(e=>status(e.message,true));
    function initSectionHub(){
      const cards = Array.from(document.querySelectorAll('.w > .c'));
      if (cards.length >= 10) {
        cards[1].id = 'settingsCard';
        cards[2].id = 'messagesCard';
        cards[3].id = 'commandsCard';
        cards[5].id = 'repliesCard';
        cards[7].id = 'levelsCard';
        cards[8].id = 'creditsCard';
        cards[9].id = 'aliasesCard';
      }

      const managedIds = ['settingsCard','messagesCard','commandsCard','repliesCard','levelsCard','creditsCard','aliasesCard'];
      managedIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.add('section-hidden');
      });

      let activeSection = null;
      let placeholder = null;

      function closeSectionModal(){
        const modal = q('sectionModal');
        if (activeSection && placeholder && placeholder.parentNode) {
          activeSection.classList.add('section-hidden');
          placeholder.parentNode.insertBefore(activeSection, placeholder);
          placeholder.remove();
        }
        activeSection = null;
        placeholder = null;
        q('sectionModalBody').innerHTML = '';
        modal.classList.remove('show');
        document.body.classList.remove('auth-locked');
      }

      q('sectionModalClose').onclick = closeSectionModal;
      q('sectionModal').onclick = (ev) => {
        if (ev.target.id === 'sectionModal') closeSectionModal();
      };

      Array.from(document.querySelectorAll('button[data-go]')).forEach(btn => {
        btn.onclick = () => {
          const target = document.getElementById(btn.getAttribute('data-go'));
          if (!target) return;
          if (activeSection) closeSectionModal();
          placeholder = document.createComment('section-slot');
          target.parentNode.insertBefore(placeholder, target);
          target.classList.remove('section-hidden');
          q('sectionModalBody').appendChild(target);
          q('sectionModalTitle').textContent = target.querySelector('h3')?.textContent || 'القسم';
          q('sectionModal').classList.add('show');
          document.body.classList.add('auth-locked');
          activeSection = target;
        };
      });
    }
    initSettingsLayout();
    initSectionHub();
    q('changeUser').onclick=()=>{
      location.href = withToken('/auth/logout');
    };
    ensureDashboardSession()
      .then(ok => { if (ok) return loadGuilds(); })
      .catch(e=>status(e.message,true));

  </script>
  </div></body></html>`;
}

async function getGuildDashboardData(client, guildId) {
  const guild = client.guilds.cache.get(guildId);
  if (!guild) return null;

  const settings = (await db.get('SELECT * FROM settings WHERE guild_id = ?', [guildId])) || {};
  const autoReplyRows = await db.all(
    `SELECT id, trigger, response, responses_json, allowed_role_ids, disabled_role_ids, excluded_channel_ids, match_mode, enabled, delete_trigger_message, send_as_reply, pinging
     FROM auto_replies
     WHERE guild_id = ?
     ORDER BY id DESC`,
    [guildId]
  );
  const autoReplies = autoReplyRows.map(row => ({
    id: row.id,
    trigger: row.trigger,
    response: row.response,
    responses: parseResponses(row),
    allowed_role_ids: parseRoleIds(row.allowed_role_ids),
    disabled_role_ids: parseRoleIds(row.disabled_role_ids),
    excluded_channel_ids: parseRoleIds(row.excluded_channel_ids),
    match_mode: row.match_mode || 'exact',
    enabled: !!row.enabled,
    delete_trigger_message: Number(row.delete_trigger_message || 0),
    send_as_reply: Number(row.send_as_reply || 0),
    pinging: Number(row.pinging || 0),
  }));

  const roles = guild.roles.cache
    .filter(role => role.id !== guild.id)
    .sort((a, b) => b.position - a.position)
    .map(role => ({ id: role.id, name: role.name, position: role.position }));
  const channels = guild.channels.cache
      .filter(channel => channel?.isTextBased?.() && channel.type !== 4)
      .sort((a, b) => {
        const posDiff = Number(a.rawPosition ?? a.position ?? 0) - Number(b.rawPosition ?? b.position ?? 0);
        if (posDiff !== 0) return posDiff;
        return String(a.name || '').localeCompare(String(b.name || ''), 'ar');
      })
      .map(channel => ({ id: channel.id, name: channel.name }));

  const blacklistRows = await db.all(
    'SELECT word FROM automod_blacklist WHERE guild_id = ? ORDER BY word ASC',
    [guildId]
  );
  const roleLevels = await db.all(
    'SELECT level, role_id FROM role_levels WHERE guild_id = ? ORDER BY level ASC',
    [guildId]
  );
  const commandAliases = await db.all(
    'SELECT id, command_name, alias_name FROM guild_command_aliases WHERE guild_id = ? ORDER BY id DESC',
    [guildId]
  );
  const commands = Array.from(client.commands.keys())
    .map(name => String(name || '').trim().toLowerCase())
    .filter(Boolean)
    .sort((a, b) => a.localeCompare(b))
    .filter((name, index, arr) => arr.indexOf(name) === index);

  return {
    guild: { id: guild.id, name: guild.name, members: guild.memberCount },
    settings,
    autoReplies,
    roles,
    channels,
    blacklist: blacklistRows.map(row => row.word),
    roleLevels,
    botMessages: await getBotMessages(guildId),
    commandAliases,
    commands,
  };
}

async function getDashboardMemberByUserId(guild, userId) {
  if (!guild || !userId) return null;
  return guild.members.fetch(userId).catch(() => guild.members.cache.get(userId) || null);
}

function memberHasDashboardAccess(member) {
  if (!member) return false;
  if (member.guild.ownerId === member.id) return true;
  return member.permissions.has('Administrator') || member.permissions.has('ManageGuild');
}

async function listAccessibleGuilds(client, userId) {
  const out = [];
  for (const guild of client.guilds.cache.values()) {
    const member = await getDashboardMemberByUserId(guild, userId);
    if (!memberHasDashboardAccess(member)) continue;
    out.push({ id: guild.id, name: guild.name, members: guild.memberCount });
  }
  out.sort((a, b) => a.name.localeCompare(b.name));
  return out;
}

function startDashboard(client) {
  const app = express();
  const port = parseIntSafe(process.env.PORT || process.env.DASHBOARD_PORT, 3000);
  const token = process.env.DASHBOARD_TOKEN || '';

  app.use(express.json({ limit: '1mb' }));
  app.use(authMiddleware(token));

  app.get('/auth/me', (req, res) => {
    const authConfig = getDashboardAuthConfig();
    if (!authConfig.isConfigured) return res.status(503).json({ error: 'discord_oauth_not_configured' });
    const user = getAuthenticatedDashboardUser(req);
    if (!user) return res.status(401).json({ error: 'not_logged_in' });
    return res.json({ user });
  });

  app.get('/auth/discord', (req, res) => {
    const authConfig = getDashboardAuthConfig();
    if (!authConfig.isConfigured) {
      return res.redirect(buildDashboardReturnUrl(String(req.query.token || ''), { auth_error: 'oauth_not_configured' }));
    }
    const nonce = crypto.randomBytes(24).toString('hex');
    const dashboardToken = String(req.query.token || '');
    setDashboardState(res, req, { nonce, dashboardToken });
    const authUrl = new URL('https://discord.com/api/oauth2/authorize');
    authUrl.searchParams.set('client_id', authConfig.clientId);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('redirect_uri', authConfig.redirectUri);
    authUrl.searchParams.set('scope', 'identify');
    authUrl.searchParams.set('state', nonce);
    return res.redirect(authUrl.toString());
  });

  app.get('/auth/callback', async (req, res) => {
    return processDiscordAuthCallback(req, res);
  });

  app.get('/auth/logout', (req, res) => {
    const dashboardToken = String(req.query.token || '');
    clearCookie(res, DASHBOARD_SESSION_COOKIE, req);
    clearCookie(res, DASHBOARD_STATE_COOKIE, req);
    return res.redirect(buildDashboardReturnUrl(dashboardToken));
  });

  app.get('/', async (req, res) => {
    if (req.query && req.query.code && req.query.state) {
      return processDiscordAuthCallback(req, res);
    }
    return res.type('html').send(buildDashboardHtml());
  });

  app.get('/api/guilds', (req, res) => {
    (async () => {
      const user = getAuthenticatedDashboardUser(req);
      if (!user) return res.status(401).json({ error: 'not_logged_in' });
      const guilds = await listAccessibleGuilds(client, user.id);
      return res.json({ guilds, user });
    })().catch(err => res.status(500).json({ error: String(err?.message || err) }));
  });

  app.get('/api/guilds/:guildId', async (req, res) => {
    const data = await getGuildDashboardData(client, req.params.guildId);
    if (!data) return res.status(404).json({ error: 'guild_not_found' });
    const user = getAuthenticatedDashboardUser(req);
    if (!user) return res.status(401).json({ error: 'not_logged_in' });
    const guilds = await listAccessibleGuilds(client, user.id);
    if (!guilds.some(g => g.id === req.params.guildId)) return res.status(403).json({ error: 'forbidden_guild' });
    return res.json({ ...data, guilds, user });
  });

  app.use('/api/guilds/:guildId', async (req, res, next) => {
    const guildId = req.params.guildId;
    const user = getAuthenticatedDashboardUser(req);
    if (!user) return res.status(401).json({ error: 'not_logged_in' });
    if (!client.guilds.cache.has(guildId)) return res.status(404).json({ error: 'guild_not_found' });

    const guild = client.guilds.cache.get(guildId);
    const member = await getDashboardMemberByUserId(guild, user.id);
    if (!memberHasDashboardAccess(member)) return res.status(403).json({ error: 'forbidden_guild' });
    return next();
  });

  app.put('/api/guilds/:guildId/settings', async (req, res) => {
    const guildId = req.params.guildId;
    if (!client.guilds.cache.has(guildId)) return res.status(404).json({ error: 'guild_not_found' });
    const p = req.body || {};
    const current = (await db.get('SELECT * FROM settings WHERE guild_id = ?', [guildId])) || {};
    const merged = { ...current, ...p };
    await db.run(
      `INSERT INTO settings (
        guild_id, welcome_channel_id, goodbye_channel_id, levelup_channel_id, cmd_channel_id, cmd_admin_channel_id,
        welcome_message, muted_role_id, ticket_category_id,
        log_roles_channel_id, log_rooms_channel_id, log_bans_channel_id, log_time_channel_id, log_kick_channel_id,
        log_message_edit_channel_id, log_message_delete_channel_id,
        automod_spam_enabled, automod_links_enabled, automod_caps_enabled, automod_warn_threshold, auto_reply_delete_trigger, stats_enabled,
        command_t_enabled, command_r_enabled, command_t_require_prefix, command_r_require_prefix, command_t_channel_mode, command_r_channel_mode, command_t_channel_ids, command_r_channel_ids, command_settings_json, custom_prefix, t_text_metric, t_voice_metric, r_style, r_text_metric, r_voice_metric
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(guild_id) DO UPDATE SET
        welcome_channel_id = excluded.welcome_channel_id,
        goodbye_channel_id = excluded.goodbye_channel_id,
        levelup_channel_id = excluded.levelup_channel_id,
        cmd_channel_id = excluded.cmd_channel_id,
        cmd_admin_channel_id = excluded.cmd_admin_channel_id,
        welcome_message = excluded.welcome_message,
        muted_role_id = excluded.muted_role_id,
        ticket_category_id = excluded.ticket_category_id,
        log_roles_channel_id = excluded.log_roles_channel_id,
        log_rooms_channel_id = excluded.log_rooms_channel_id,
        log_bans_channel_id = excluded.log_bans_channel_id,
        log_time_channel_id = excluded.log_time_channel_id,
        log_kick_channel_id = excluded.log_kick_channel_id,
        log_message_edit_channel_id = excluded.log_message_edit_channel_id,
        log_message_delete_channel_id = excluded.log_message_delete_channel_id,
        automod_spam_enabled = excluded.automod_spam_enabled,
        automod_links_enabled = excluded.automod_links_enabled,
        automod_caps_enabled = excluded.automod_caps_enabled,
        automod_warn_threshold = excluded.automod_warn_threshold,
        auto_reply_delete_trigger = excluded.auto_reply_delete_trigger,
        stats_enabled = excluded.stats_enabled,
        command_t_enabled = excluded.command_t_enabled,
        command_r_enabled = excluded.command_r_enabled,
        command_t_require_prefix = excluded.command_t_require_prefix,
        command_r_require_prefix = excluded.command_r_require_prefix,
        command_t_channel_mode = excluded.command_t_channel_mode,
        command_r_channel_mode = excluded.command_r_channel_mode,
        command_t_channel_ids = excluded.command_t_channel_ids,
        command_r_channel_ids = excluded.command_r_channel_ids,
        command_settings_json = excluded.command_settings_json,
        custom_prefix = excluded.custom_prefix,
        t_text_metric = excluded.t_text_metric,
        t_voice_metric = excluded.t_voice_metric,
        r_style = excluded.r_style,
        r_text_metric = excluded.r_text_metric,
        r_voice_metric = excluded.r_voice_metric`,
      [
        guildId,
        merged.welcome_channel_id || null,
        merged.goodbye_channel_id || null,
        merged.levelup_channel_id || null,
        merged.cmd_channel_id || null,
        merged.cmd_admin_channel_id || null,
        merged.welcome_message || null,
        merged.muted_role_id || null,
        merged.ticket_category_id || null,
        merged.log_roles_channel_id || null,
        merged.log_rooms_channel_id || null,
        merged.log_bans_channel_id || null,
        merged.log_time_channel_id || null,
        merged.log_kick_channel_id || null,
        merged.log_message_edit_channel_id || null,
        merged.log_message_delete_channel_id || null,
        toFlag(merged.automod_spam_enabled),
        toFlag(merged.automod_links_enabled),
        toFlag(merged.automod_caps_enabled),
        parseIntSafe(merged.automod_warn_threshold, 5),
        toFlag(merged.auto_reply_delete_trigger),
        toFlag(merged.stats_enabled),
        toFlag(merged.command_t_enabled),
        toFlag(merged.command_r_enabled),
        toFlag(merged.command_t_require_prefix),
        toFlag(merged.command_r_require_prefix),
        String(merged.command_t_channel_mode || 'any'),
        String(merged.command_r_channel_mode || 'any'),
        String(merged.command_t_channel_ids || ''),
        String(merged.command_r_channel_ids || ''),
        JSON.stringify(merged.command_settings_json && typeof merged.command_settings_json === 'object' ? merged.command_settings_json : (() => { try { return JSON.parse(String(merged.command_settings_json || '{}')); } catch (_) { return {}; } })()),
        String(merged.custom_prefix || ''),
        String(merged.t_text_metric || 'xp'),
        String(merged.t_voice_metric || 'xp'),
        String(merged.r_style || 'image'),
        String(merged.r_text_metric || 'xp'),
        String(merged.r_voice_metric || 'xp'),
      ]
    );
    return res.json({ ok: true });
  });

  app.get('/api/guilds/:guildId/bot-messages', async (req, res) => {
    const guildId = req.params.guildId;
    if (!client.guilds.cache.has(guildId)) return res.status(404).json({ error: 'guild_not_found' });
    return res.json({ messages: await getBotMessages(guildId) });
  });

  app.put('/api/guilds/:guildId/bot-messages', async (req, res) => {
    const guildId = req.params.guildId;
    if (!client.guilds.cache.has(guildId)) return res.status(404).json({ error: 'guild_not_found' });
    const messages = req.body?.messages || {};
    for (const key of Object.keys(DEFAULT_BOT_MESSAGES)) {
      const text = String(messages[key] || '').trim();
      if (!text) continue;
      await db.run(
        `INSERT INTO bot_messages (guild_id, message_key, message_text, updated_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(guild_id, message_key) DO UPDATE SET
           message_text = excluded.message_text, updated_at = excluded.updated_at`,
        [guildId, key, text, Math.floor(Date.now() / 1000)]
      );
    }
    return res.json({ ok: true });
  });

  app.get('/api/guilds/:guildId/auto-replies', async (req, res) => {
    const guildId = req.params.guildId;
    const rows = await db.all(
      `SELECT id, trigger, response, responses_json, allowed_role_ids, disabled_role_ids, excluded_channel_ids, match_mode, enabled, delete_trigger_message, send_as_reply, pinging
       FROM auto_replies WHERE guild_id = ? ORDER BY id DESC`,
      [guildId]
    );
    const items = rows.map(row => ({
      id: row.id,
      trigger: row.trigger,
      response: row.response,
      responses: parseResponses(row),
      allowed_role_ids: parseRoleIds(row.allowed_role_ids),
      disabled_role_ids: parseRoleIds(row.disabled_role_ids),
      excluded_channel_ids: parseRoleIds(row.excluded_channel_ids),
      match_mode: row.match_mode || 'exact',
      enabled: !!row.enabled,
      delete_trigger_message: Number(row.delete_trigger_message || 0),
      send_as_reply: Number(row.send_as_reply || 0),
      pinging: Number(row.pinging || 0),
    }));
    res.json({ items });
  });

  app.post('/api/guilds/:guildId/auto-replies', async (req, res) => {
    const guildId = req.params.guildId;
    const n = normalizeAutoReplyPayload(req.body || {});
    if (!n.trigger || !n.response) return res.status(400).json({ error: 'trigger_and_response_required' });
    await db.run(
      `INSERT INTO auto_replies (
        guild_id, trigger, response, responses_json, allowed_role_ids, disabled_role_ids, excluded_channel_ids, match_mode, enabled, delete_trigger_message, send_as_reply, pinging
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(guild_id, trigger) DO UPDATE SET
        response = excluded.response,
        responses_json = excluded.responses_json,
        allowed_role_ids = excluded.allowed_role_ids,
        disabled_role_ids = excluded.disabled_role_ids,
        excluded_channel_ids = excluded.excluded_channel_ids,
        match_mode = excluded.match_mode,
        enabled = excluded.enabled,
        delete_trigger_message = excluded.delete_trigger_message,
        send_as_reply = excluded.send_as_reply,
        pinging = excluded.pinging`,
      [guildId, n.trigger, n.response, n.responses_json, n.allowed_role_ids, n.disabled_role_ids, n.excluded_channel_ids, n.match_mode, n.enabled, n.delete_trigger_message, n.send_as_reply, n.pinging]
    );
    res.json({ ok: true });
  });

  app.put('/api/guilds/:guildId/auto-replies/:id', async (req, res) => {
    const guildId = req.params.guildId;
    const id = parseIntSafe(req.params.id, 0);
    if (!id) return res.status(400).json({ error: 'invalid_id' });
    const existing = await db.get(
      'SELECT id, trigger, response, responses_json, allowed_role_ids, disabled_role_ids, excluded_channel_ids, match_mode, enabled, delete_trigger_message, send_as_reply, pinging FROM auto_replies WHERE guild_id = ? AND id = ?',
      [guildId, id]
    );
    if (!existing) return res.status(404).json({ error: 'not_found' });

    const payload = req.body || {};
    const toggleOnly = Object.keys(payload).length === 1 && Object.prototype.hasOwnProperty.call(payload, 'enabled');
    if (toggleOnly) {
      const enabled = payload.enabled === 1 ? 1 : 0;
      await db.run('UPDATE auto_replies SET enabled = ? WHERE guild_id = ? AND id = ?', [enabled, guildId, id]);
      return res.json({ ok: true });
    }

    const n = normalizeAutoReplyPayload({
      trigger: payload.trigger ?? existing.trigger,
      response: payload.response ?? existing.response,
      responsesText: payload.responsesText,
      responses: payload.responses,
      allowed_role_ids: payload.allowed_role_ids ?? existing.allowed_role_ids,
      disabled_role_ids: payload.disabled_role_ids ?? existing.disabled_role_ids,
      excluded_channel_ids: payload.excluded_channel_ids ?? existing.excluded_channel_ids,
      match_mode: payload.match_mode ?? existing.match_mode,
      enabled: payload.enabled ?? existing.enabled,
      delete_trigger_message: payload.delete_trigger_message ?? existing.delete_trigger_message,
      send_as_reply: payload.send_as_reply ?? existing.send_as_reply,
      pinging: payload.pinging ?? existing.pinging,
    });

    if (!n.trigger || !n.response) return res.status(400).json({ error: 'trigger_and_response_required' });
    await db.run(
      `UPDATE auto_replies
       SET trigger = ?, response = ?, responses_json = ?, allowed_role_ids = ?, disabled_role_ids = ?, excluded_channel_ids = ?, match_mode = ?, enabled = ?, delete_trigger_message = ?, send_as_reply = ?, pinging = ?
       WHERE guild_id = ? AND id = ?`,
      [n.trigger, n.response, n.responses_json, n.allowed_role_ids, n.disabled_role_ids, n.excluded_channel_ids, n.match_mode, n.enabled, n.delete_trigger_message, n.send_as_reply, n.pinging, guildId, id]
    );
    res.json({ ok: true });
  });

  app.delete('/api/guilds/:guildId/auto-replies/:id', async (req, res) => {
    const guildId = req.params.guildId;
    const id = parseIntSafe(req.params.id, 0);
    if (!id) return res.status(400).json({ error: 'invalid_id' });
    await db.run('DELETE FROM auto_replies WHERE guild_id = ? AND id = ?', [guildId, id]);
    res.json({ ok: true });
  });

  app.get('/api/guilds/:guildId/command-aliases', async (req, res) => {
    const guildId = req.params.guildId;
    if (!client.guilds.cache.has(guildId)) return res.status(404).json({ error: 'guild_not_found' });
    const items = await db.all(
      'SELECT id, command_name, alias_name FROM guild_command_aliases WHERE guild_id = ? ORDER BY id DESC',
      [guildId]
    );
    const commands = Array.from(client.commands.keys())
      .map(name => String(name || '').trim().toLowerCase())
      .filter(Boolean)
      .sort((a, b) => a.localeCompare(b))
      .filter((name, index, arr) => arr.indexOf(name) === index);
    return res.json({ items, commands });
  });

  app.post('/api/guilds/:guildId/command-aliases', async (req, res) => {
    const guildId = req.params.guildId;
    if (!client.guilds.cache.has(guildId)) return res.status(404).json({ error: 'guild_not_found' });
    const n = normalizeCommandAliasPayload(req.body || {});
    if (!n.command_name || !n.alias_name) return res.status(400).json({ error: 'command_and_alias_required' });
    if (n.alias_name.length > 32) return res.status(400).json({ error: 'alias_too_long' });
    if (!client.commands.has(n.command_name)) return res.status(400).json({ error: 'unknown_command' });

    const existingNative = client.commands.get(n.alias_name);
    if (existingNative && n.alias_name !== n.command_name) {
      return res.status(400).json({ error: 'alias_conflicts_with_existing_command' });
    }

    await db.run(
      `INSERT INTO guild_command_aliases (guild_id, command_name, alias_name, created_at)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(guild_id, alias_name) DO UPDATE SET command_name = excluded.command_name`,
      [guildId, n.command_name, n.alias_name, Math.floor(Date.now() / 1000)]
    );
    return res.json({ ok: true });
  });

  app.delete('/api/guilds/:guildId/command-aliases/:id', async (req, res) => {
    const guildId = req.params.guildId;
    const id = parseIntSafe(req.params.id, 0);
    if (!id) return res.status(400).json({ error: 'invalid_id' });
    await db.run('DELETE FROM guild_command_aliases WHERE guild_id = ? AND id = ?', [guildId, id]);
    return res.json({ ok: true });
  });

  app.post('/api/guilds/:guildId/blacklist', async (req, res) => {
    const guildId = req.params.guildId;
    const word = String(req.body?.word || '').trim();
    if (!word) return res.status(400).json({ error: 'word_required' });
    await db.run('INSERT OR IGNORE INTO automod_blacklist (guild_id, word) VALUES (?, ?)', [guildId, word]);
    return res.json({ ok: true });
  });

  app.delete('/api/guilds/:guildId/blacklist/:word', async (req, res) => {
    const guildId = req.params.guildId;
    const word = decodeURIComponent(req.params.word);
    await db.run('DELETE FROM automod_blacklist WHERE guild_id = ? AND word = ?', [guildId, word]);
    return res.json({ ok: true });
  });

  app.post('/api/guilds/:guildId/role-levels', async (req, res) => {
    const guildId = req.params.guildId;
    const level = parseIntSafe(req.body?.level, 0);
    const roleId = String(req.body?.role_id || '').trim();
    if (!level || !roleId) return res.status(400).json({ error: 'level_and_role_required' });
    await db.run(
      `INSERT INTO role_levels (guild_id, level, role_id)
       VALUES (?, ?, ?)
       ON CONFLICT(guild_id, level) DO UPDATE SET role_id = excluded.role_id`,
      [guildId, level, roleId]
    );
    return res.json({ ok: true });
  });

  app.delete('/api/guilds/:guildId/role-levels/:level', async (req, res) => {
    const guildId = req.params.guildId;
    const level = parseIntSafe(req.params.level, 0);
    if (!level) return res.status(400).json({ error: 'invalid_level' });
    await db.run('DELETE FROM role_levels WHERE guild_id = ? AND level = ?', [guildId, level]);
    return res.json({ ok: true });
  });

  app.get('/api/guilds/:guildId/credits', async (req, res) => {
    const guildId = req.params.guildId;
    const limit = Math.max(1, Math.min(50, parseIntSafe(req.query.limit, 20)));
    const rows = await db.all(
      'SELECT user_id, balance FROM credits WHERE guild_id = ? ORDER BY balance DESC LIMIT ?',
      [guildId, limit]
    );
    const guild = client.guilds.cache.get(guildId);
    const items = await Promise.all(rows.map(async row => {
      const member = guild ? await guild.members.fetch(row.user_id).catch(() => null) : null;
      return {
        ...row,
        display_name: member ? `${member.user.username} (${member.id})` : row.user_id,
      };
    }));
    res.json({ items });
  });

  app.post('/api/guilds/:guildId/credits/set', async (req, res) => {
    const guildId = req.params.guildId;
    const userId = String(req.body?.user_id || '').trim();
    const balance = parseIntSafe(req.body?.balance, NaN);
    if (!userId || !Number.isFinite(balance) || balance < 0) {
      return res.status(400).json({ error: 'invalid_payload' });
    }
    const now = Math.floor(Date.now() / 1000);
    await db.run(
      'INSERT OR IGNORE INTO credits (guild_id, user_id, balance, daily_next, updated_at) VALUES (?, ?, 0, 0, ?)',
      [guildId, userId, now]
    );
    await db.run(
      'UPDATE credits SET balance = ?, updated_at = ? WHERE guild_id = ? AND user_id = ?',
      [balance, now, guildId, userId]
    );
    res.json({ ok: true });
  });

  app.post('/api/guilds/:guildId/credits/add', async (req, res) => {
    const guildId = req.params.guildId;
    const userId = String(req.body?.user_id || '').trim();
    const amount = parseIntSafe(req.body?.amount, NaN);
    if (!userId || !Number.isFinite(amount)) {
      return res.status(400).json({ error: 'invalid_payload' });
    }
    const now = Math.floor(Date.now() / 1000);
    await db.run(
      'INSERT OR IGNORE INTO credits (guild_id, user_id, balance, daily_next, updated_at) VALUES (?, ?, 0, 0, ?)',
      [guildId, userId, now]
    );
    const current = await db.get('SELECT balance FROM credits WHERE guild_id = ? AND user_id = ?', [guildId, userId]);
    const nextBalance = Math.max(0, (current?.balance || 0) + amount);
    await db.run(
      'UPDATE credits SET balance = ?, updated_at = ? WHERE guild_id = ? AND user_id = ?',
      [nextBalance, now, guildId, userId]
    );
    res.json({ ok: true, balance: nextBalance });
  });

  app.get('/stats', (req, res) => res.redirect('/api/guilds'));
  app.get('/giveaways', async (req, res) => {
    const rows = await db.all(
      'SELECT id, guild_id, prize, ends_at, ended, winners_count FROM giveaways ORDER BY id DESC LIMIT 100'
    );
    res.json({ giveaways: rows });
  });
  app.use((err, req, res, next) => {
    console.error('dashboard error:', err);
    res.status(500).json({ error: 'internal_error' });
  });

  const startPort = port;
  const maxPort = startPort + 20;

  const listenWithFallback = (candidatePort) => {
    const server = app.listen(candidatePort, '0.0.0.0', () => {
      console.log(`Dashboard listening on ${candidatePort}`);
    });

    server.on('error', (err) => {
      if (err?.code === 'EADDRINUSE' && candidatePort < maxPort) {
        const nextPort = candidatePort + 1;
        console.warn(`Port ${candidatePort} is in use, trying ${nextPort}...`);
        setTimeout(() => listenWithFallback(nextPort), 50);
        return;
      }
      console.error('Failed to start dashboard listener:', err);
    });
  };

  listenWithFallback(startPort);
}

module.exports = { startDashboard };




