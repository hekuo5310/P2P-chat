export interface Env { DB: D1Database; EPHEMERAL: KVNamespace; ASSETS: Fetcher; EMAIL: SendEmail; MAIL_FROM: string }
type Json = Record<string, unknown>;
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
const bad = (message: string, status = 400) => json({ error: message }, status);
const id = () => crypto.randomUUID();
const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
async function hash(value: string) { return b64(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)))); }
async function body(request: Request): Promise<Json | null> { try { const x = await request.json(); return x && typeof x === "object" ? x as Json : null; } catch { return null; } }
function text(x: unknown, max = 200) { return typeof x === "string" && x.trim() && x.length <= max ? x.trim() : null; }
async function auth(request: Request, env: Env) {
  const userId = request.headers.get("x-user-id"); const token = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "");
  if (!userId || !token) return null;
  const user = await env.DB.prepare("SELECT id, display_name, encryption_key FROM users WHERE id = ? AND token_hash = ?").bind(userId, await hash(token)).first<{id:string;display_name:string;encryption_key:string;signing_key:string}>();
  return user ?? null;
}
async function member(env: Env, groupId: string, userId: string) { return !!await env.DB.prepare("SELECT 1 FROM group_members WHERE group_id=? AND user_id=?").bind(groupId, userId).first(); }
async function message(env: Env, groupId: string, messageId: string) { return env.EPHEMERAL.get(`group:${groupId}:message:${messageId}`, "json") as Promise<GroupMessage | null>; }
type GroupMessage = { id:string; senderId:string; ciphertext:unknown; wrappedKeys:Record<string, unknown>; signature:string; recipients:string[]; receipts:string[]; createdAt:number };
const email = (x: unknown) => typeof x === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(x.trim()) && x.length <= 254 ? x.trim().toLowerCase() : null;
async function sendCode(env: Env, to: string, code: string) {
  await env.EMAIL.send({ from: env.MAIL_FROM, to, subject: "P2P Chat 登录验证码", text: `你的 P2P Chat 验证码是：${code}。10 分钟内有效；若不是你本人操作，请忽略此邮件。`, html: `<div style=\"font-family:Arial,sans-serif\"><h2>P2P Chat</h2><p>你的验证码是：</p><p style=\"font-size:28px;letter-spacing:6px;font-weight:700\">${code}</p><p>10 分钟内有效。若不是你本人操作，请忽略此邮件。</p></div>` });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url); const path = url.pathname;
    if (!path.startsWith("/api/")) return env.ASSETS.fetch(request);
    if (request.method === "OPTIONS") return new Response(null, { headers: { "access-control-allow-origin": url.origin, "access-control-allow-headers": "content-type, authorization, x-user-id", "access-control-allow-methods": "GET,POST,OPTIONS" } });
    try {
      if (path === "/api/auth/request-code" && request.method === "POST") {
        const x = await body(request), address = email(x?.email), displayName = text(x?.displayName, 40), encryptionKey = text(x?.encryptionKey, 4096), signingKey = text(x?.signingKey, 4096);
        if (!address || !displayName || !encryptionKey || !signingKey) return bad("email, displayName, encryptionKey and signingKey are required");
        if (await env.EPHEMERAL.get(`auth:cooldown:${address}`)) return bad("请稍后再请求验证码", 429);
        const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 900000 + 100000);
        await sendCode(env, address, code);
        await env.EPHEMERAL.put(`auth:code:${address}`, JSON.stringify({ codeHash: await hash(code), displayName, encryptionKey, signingKey }), { expirationTtl: 600 });
        await env.EPHEMERAL.put(`auth:cooldown:${address}`, "1", { expirationTtl: 60 });
        return json({ ok: true, expiresIn: 600 });
      }
      if (path === "/api/auth/verify-code" && request.method === "POST") {
        const x = await body(request), address = email(x?.email), code = text(x?.code, 6); if (!address || !code) return bad("email and 6 digit code are required");
        const pending = await env.EPHEMERAL.get<{codeHash:string;displayName:string;encryptionKey:string;signingKey:string}>(`auth:code:${address}`, "json");
        if (!pending || pending.codeHash !== await hash(code)) return bad("验证码无效或已过期", 401);
        let user = await env.DB.prepare("SELECT id,display_name,encryption_key,signing_key FROM users WHERE email=?").bind(address).first<{id:string;display_name:string;encryption_key:string}>();
        const token = b64(crypto.getRandomValues(new Uint8Array(32)));
        if (user) { await env.DB.prepare("UPDATE users SET token_hash=?, display_name=? WHERE id=?").bind(await hash(token), pending.displayName, user.id).run(); user = { ...user, display_name: pending.displayName }; }
        else { const userId = id(); await env.DB.prepare("INSERT INTO users (id,email,display_name,encryption_key,signing_key,token_hash,created_at) VALUES (?,?,?,?,?,?,?)").bind(userId,address,pending.displayName,pending.encryptionKey,pending.signingKey,await hash(token),Date.now()).run(); user={id:userId,display_name:pending.displayName,encryption_key:pending.encryptionKey,signing_key:pending.signingKey}; }
        await env.EPHEMERAL.delete(`auth:code:${address}`); return json({ id:user.id, token, displayName:user.display_name, email:address, encryptionKey:user.encryption_key });
      }
      const userMatch = path.match(/^\/api\/users\/([\w-]+)$/);
      if (userMatch && request.method === "GET") {
        const user = await env.DB.prepare("SELECT id,display_name,encryption_key,signing_key FROM users WHERE id=?").bind(userMatch[1]).first(); return user ? json(user) : bad("user not found", 404);
      }
      if (path === "/api/users/search" && request.method === "GET") {
        const q = url.searchParams.get("q")?.trim() ?? ""; if (!q) return json([]);
        const r = await env.DB.prepare("SELECT id,display_name FROM users WHERE display_name LIKE ? LIMIT 10").bind(`%${q}%`).all(); return json(r.results);
      }
      const me = await auth(request, env); if (!me) return bad("authentication required", 401);
      if (path === "/api/presence" && request.method === "POST") { await env.EPHEMERAL.put(`presence:${me.id}`, "1", { expirationTtl: 90 }); return json({ ok: true }); }
      const presence = path.match(/^\/api\/presence\/([\w-]+)$/);
      if (presence && request.method === "GET") return json({ online: !!await env.EPHEMERAL.get(`presence:${presence[1]}`) });
      if (path === "/api/signals" && request.method === "POST") {
        const x = await body(request), to = text(x?.to, 64), sessionId = text(x?.sessionId, 100), type = text(x?.type, 12);
        if (!to || !sessionId || !["offer", "answer"].includes(type ?? "") || x?.payload === undefined) return bad("invalid signal");
        await env.EPHEMERAL.put(`signal:${to}:${sessionId}:${type}`, JSON.stringify({ from: me.id, payload: x.payload, signature: x.signature }), { expirationTtl: 600 }); return json({ ok: true });
      }
      const signal = path.match(/^\/api\/signals\/([\w-]+)$/);
      if (signal && request.method === "GET") { const offer = await env.EPHEMERAL.get(`signal:${me.id}:${signal[1]}:offer`, "json"); const answer = await env.EPHEMERAL.get(`signal:${me.id}:${signal[1]}:answer`, "json"); return json({ offer, answer }); }
      if (path === "/api/groups" && request.method === "POST") {
        const x = await body(request), title = text(x?.title, 80); if (!title) return bad("title is required"); const groupId = id();
        await env.DB.batch([env.DB.prepare("INSERT INTO chat_groups (id,title,owner_id,created_at) VALUES (?,?,?,?)").bind(groupId,title,me.id,Date.now()), env.DB.prepare("INSERT INTO group_members (group_id,user_id,joined_at) VALUES (?,?,?)").bind(groupId,me.id,Date.now())]); return json({ id: groupId, title });
      }
      if (path === "/api/groups" && request.method === "GET") { const r = await env.DB.prepare("SELECT g.id,g.title,g.owner_id,g.created_at FROM chat_groups g JOIN group_members m ON m.group_id=g.id WHERE m.user_id=? ORDER BY g.created_at DESC").bind(me.id).all(); return json(r.results); }
      const group = path.match(/^\/api\/groups\/([\w-]+)$/);
      if (group && request.method === "GET") { if (!await member(env, group[1], me.id)) return bad("not a member",403); const g=await env.DB.prepare("SELECT id,title,owner_id,created_at FROM chat_groups WHERE id=?").bind(group[1]).first(); const ms=await env.DB.prepare("SELECT u.id,u.display_name,u.encryption_key,u.signing_key FROM users u JOIN group_members m ON m.user_id=u.id WHERE m.group_id=?").bind(group[1]).all(); return g?json({...g,members:ms.results}):bad("group not found",404); }
      const members = path.match(/^\/api\/groups\/([\w-]+)\/members$/);
      if (members && request.method === "POST") { const x=await body(request), userId=text(x?.userId,64); const g=await env.DB.prepare("SELECT owner_id FROM chat_groups WHERE id=?").bind(members[1]).first<{owner_id:string}>(); if(!g)return bad("group not found",404); if(g.owner_id!==me.id)return bad("only owner can add members",403); if(!userId || !await env.DB.prepare("SELECT 1 FROM users WHERE id=?").bind(userId).first())return bad("user not found",404); await env.DB.prepare("INSERT OR IGNORE INTO group_members (group_id,user_id,joined_at) VALUES (?,?,?)").bind(members[1],userId,Date.now()).run(); return json({ok:true}); }
      const messages = path.match(/^\/api\/groups\/([\w-]+)\/messages$/);
      if (messages && request.method === "POST") {
        const groupId=messages[1]; if(!await member(env,groupId,me.id))return bad("not a member",403); const x=await body(request); if(x?.ciphertext===undefined || !x.wrappedKeys || typeof x.wrappedKeys!=="object" || !text(x.signature,4096))return bad("ciphertext, wrappedKeys and signature required");
        const recipients=(await env.DB.prepare("SELECT user_id FROM group_members WHERE group_id=? AND user_id!=?").bind(groupId,me.id).all<{user_id:string}>()).results.map(x=>x.user_id); const keys=x.wrappedKeys as Record<string,unknown>;
        if(!recipients.every(userId=>keys[userId] !== undefined))return bad("a wrapped key is required for every recipient"); const m:GroupMessage={id:id(),senderId:me.id,ciphertext:x.ciphertext,wrappedKeys:keys,signature:x.signature as string,recipients,receipts:[],createdAt:Date.now()}; await env.EPHEMERAL.put(`group:${groupId}:message:${m.id}`,JSON.stringify(m),{expirationTtl:86400}); return json({id:m.id, awaiting:recipients.length});
      }
      if (messages && request.method === "GET") { const groupId=messages[1]; if(!await member(env,groupId,me.id))return bad("not a member",403); const listed=await env.EPHEMERAL.list({prefix:`group:${groupId}:message:`,limit:100}); const out=[]; for(const k of listed.keys){const m=await env.EPHEMERAL.get<GroupMessage>(k.name,"json"); if(!m)continue; const released=m.recipients.every(r=>m.receipts.includes(r)); out.push({id:m.id,senderId:m.senderId,ciphertext:m.ciphertext,signature:m.signature,released,wrappedKey:released?m.wrappedKeys[me.id]:undefined,createdAt:m.createdAt,receipts:m.receipts.length,expected:m.recipients.length});} return json(out.sort((a,b)=>a.createdAt-b.createdAt)); }
      const receipt=path.match(/^\/api\/groups\/([\w-]+)\/messages\/([\w-]+)\/receipt$/);
      if(receipt && request.method==="POST"){const [groupId,messageId]=[receipt[1],receipt[2]];if(!await member(env,groupId,me.id))return bad("not a member",403);const m=await message(env,groupId,messageId);if(!m)return bad("message not found",404);if(!m.recipients.includes(me.id))return bad("sender cannot acknowledge",403);if(!m.receipts.includes(me.id)){m.receipts.push(me.id);await env.EPHEMERAL.put(`group:${groupId}:message:${messageId}`,JSON.stringify(m),{expirationTtl:86400});}return json({ok:true,released:m.recipients.every(r=>m.receipts.includes(r))});}
      return bad("not found",404);
    } catch (error) { console.error(error); return bad("server error",500); }
  }
} satisfies ExportedHandler<Env>;
