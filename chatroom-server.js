// ══════════════════════════════════════════════════════════════
//  چت روم — سرور یکپارچه (HTTP + WebSocket روی یک پورت)
//  لوکال:   node chatroom-server.js  → http://localhost:3000
//  Railway: خودکار از PORT می‌خواند
//  بدون npm install
// ══════════════════════════════════════════════════════════════
'use strict';

const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const os     = require('os');

// Railway / Render / Heroku همه PORT را از env می‌دهند
const PORT = parseInt(process.env.PORT || '3000', 10);

// ── IP های شبکه محلی ──────────────────────────────────────────
function getLocalIPs() {
  const ips = [];
  Object.values(os.networkInterfaces()).forEach(list =>
    (list || []).forEach(i => { if (i.family === 'IPv4' && !i.internal) ips.push(i.address); })
  );
  return ips;
}

// ══════════════════════════════════════════════════════════════
//  WebSocket — دستی، بدون پکیج
// ══════════════════════════════════════════════════════════════
const WS_MAGIC = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

function wsHandshake(socket, headers) {
  const key = headers['sec-websocket-key'];
  if (!key) { socket.destroy(); return false; }
  const accept = crypto.createHash('sha1').update(key + WS_MAGIC).digest('base64');
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
    'Sec-WebSocket-Accept: ' + accept + '\r\n\r\n'
  );
  return true;
}

function parseFrame(buf) {
  if (buf.length < 2) return null;
  const masked = (buf[1] & 0x80) !== 0;
  let len = buf[1] & 0x7f, off = 2;
  if (len === 126) { if (buf.length < 4) return null; len = buf.readUInt16BE(2); off = 4; }
  else if (len === 127) { if (buf.length < 10) return null; len = Number(buf.readBigUInt64BE(2)); off = 10; }
  const moff = masked ? off : -1;
  if (masked) off += 4;
  if (buf.length < off + len) return null;
  let p = Buffer.from(buf.slice(off, off + len));
  if (masked) { const mk = buf.slice(moff, moff + 4); for (let i = 0; i < p.length; i++) p[i] ^= mk[i % 4]; }
  return { op: buf[0] & 0x0f, payload: p, total: off + len };
}

function makeFrame(data) {
  const p = Buffer.from(data, 'utf8'), l = p.length;
  let h;
  if (l < 126)        { h = Buffer.alloc(2);  h[0] = 0x81; h[1] = l; }
  else if (l < 65536) { h = Buffer.alloc(4);  h[0] = 0x81; h[1] = 126; h.writeUInt16BE(l, 2); }
  else                { h = Buffer.alloc(10); h[0] = 0x81; h[1] = 127; h.writeBigUInt64BE(BigInt(l), 2); }
  return Buffer.concat([h, p]);
}

function wsSend(c, obj) {
  if (!c?.socket?.writable) return;
  try { c.socket.write(makeFrame(typeof obj === 'string' ? obj : JSON.stringify(obj))); } catch {}
}

// ══════════════════════════════════════════════════════════════
//  ابزار
// ══════════════════════════════════════════════════════════════
let _seq = 1;
const genId    = p => (p || '') + (_seq++) + '_' + crypto.randomBytes(3).toString('hex');
const genToken = ()  => crypto.randomBytes(28).toString('hex');
const genCode  = ()  => crypto.randomBytes(4).toString('hex').toUpperCase();
const hashPw   = (pw, salt) => crypto.pbkdf2Sync(pw, salt, 10000, 32, 'sha256').toString('hex');
const now      = ()  => Date.now();

const COLORS = ['#5865F2','#EB459E','#57F287','#FEE75C','#ED4245',
                '#3498db','#9b59b6','#e67e22','#1abc9c','#e74c3c'];
const avColor = name => COLORS[Math.abs((name || 'X').charCodeAt(0)) % COLORS.length];

// ══════════════════════════════════════════════════════════════
//  دیتابیس RAM
// ══════════════════════════════════════════════════════════════
const DB = {
  users:    new Map(),
  byName:   new Map(),
  sessions: new Map(),
  rooms:    new Map(),
  msgs:     new Map(),
};

function mkUser(username, password, displayName) {
  const id   = genId('u');
  const salt = crypto.randomBytes(16).toString('hex');
  return {
    id, username: username.toLowerCase().trim(),
    displayName: (displayName || username).trim(),
    avatar: null, color: avColor(displayName || username),
    hash: hashPw(password, salt), salt,
    bio: '', createdAt: now(), status: 'offline', lastSeen: now(),
  };
}
function mkRoom(name, ownerId, opts = {}) {
  const id = genId('r');
  return {
    id, name: name.trim(),
    description: (opts.description || '').trim(),
    icon: opts.icon || '💬', category: opts.category || 'عمومی',
    ownerId, admins: [ownerId], members: [ownerId],
    isPublic: opts.isPublic !== false,
    inviteCode: genCode(), createdAt: now(),
    lastMsg: null, pinnedMsgId: null,
  };
}
function mkMsg(senderId, roomId, type, content, replyToId) {
  return {
    id: genId('m'), senderId, roomId, type, content,
    replyToId: replyToId || null, reactions: {},
    edited: false, deleted: false, createdAt: now(),
  };
}

// ── Seed ───────────────────────────────────────────────────────
;(function seed() {
  [
    { un:'ali',    pw:'1234', dn:'علی رضایی'  },
    { un:'sara',   pw:'1234', dn:'سارا احمدی' },
    { un:'reza',   pw:'1234', dn:'رضا کریمی'  },
    { un:'maryam', pw:'1234', dn:'مریم موسوی' },
    { un:'hasan',  pw:'1234', dn:'حسن نجفی'   },
  ].forEach(x => {
    const u = mkUser(x.un, x.pw, x.dn);
    DB.users.set(u.id, u); DB.byName.set(u.username, u.id);
  });

  const aliId = DB.byName.get('ali');
  [
    { name:'عمومی',        icon:'🌍', cat:'عمومی',    desc:'گفتگوی عمومی'   },
    { name:'برنامه‌نویسی', icon:'💻', cat:'تکنولوژی', desc:'کد و تکنولوژی'   },
    { name:'گیمینگ',       icon:'🎮', cat:'سرگرمی',  desc:'دنیای بازی'       },
    { name:'موسیقی',       icon:'🎵', cat:'هنر',     desc:'موسیقی و هنر'     },
    { name:'فیلم و سریال', icon:'🎬', cat:'سرگرمی',  desc:'سینما و سریال'    },
    { name:'ورزش',         icon:'⚽', cat:'ورزش',    desc:'دنیای ورزش'       },
  ].forEach(rd => {
    const room = mkRoom(rd.name, aliId, { description:rd.desc, icon:rd.icon, category:rd.cat, isPublic:true });
    DB.users.forEach(u => { if (!room.members.includes(u.id)) room.members.push(u.id); });
    DB.rooms.set(room.id, room);
    DB.msgs.set(room.id, []);
    const sys = mkMsg('system', room.id, 'system', `🎉 به اتاق ${rd.name} خوش آمدید!`);
    DB.msgs.get(room.id).push(sys);
    room.lastMsg = { text: sys.content, senderId:'system', at: sys.createdAt };
  });
  console.log('✅ داده‌های اولیه آماده شد');
})();

// ══════════════════════════════════════════════════════════════
//  کلاینت‌های فعال
// ══════════════════════════════════════════════════════════════
const clients = new Map(); // userId → Set<clientObj>

function addClient(uid, c)    { if (!clients.has(uid)) clients.set(uid, new Set()); clients.get(uid).add(c); }
function removeClient(uid, c) { const s = clients.get(uid); if (s) { s.delete(c); if (!s.size) clients.delete(uid); } }
function sendTo(uid, data)    { clients.get(uid)?.forEach(c => wsSend(c, data)); }
function bcastRoom(roomId, data, skip) {
  DB.rooms.get(roomId)?.members.forEach(uid => { if (uid !== skip) sendTo(uid, data); });
}
function bcastAll(data) { clients.forEach(set => set.forEach(c => wsSend(c, data))); }
function onlineInRoom(roomId) {
  return (DB.rooms.get(roomId)?.members || []).filter(uid => clients.has(uid)).length;
}
function onlineList() { return [...clients.keys()]; }

// ══════════════════════════════════════════════════════════════
//  Serializers
// ══════════════════════════════════════════════════════════════
function serUser(u, force) {
  return { id:u.id, username:u.username, displayName:u.displayName,
    avatar:u.avatar, color:u.color, bio:u.bio,
    status:(force||clients.has(u.id))?'online':'offline', lastSeen:u.lastSeen };
}
function serRoom(r) {
  return { id:r.id, name:r.name, description:r.description, icon:r.icon,
    category:r.category, ownerId:r.ownerId, admins:r.admins,
    memberCount:r.members.length, onlineCount:onlineInRoom(r.id),
    isPublic:r.isPublic, inviteCode:r.inviteCode,
    lastMsg:r.lastMsg, pinnedMsgId:r.pinnedMsgId, createdAt:r.createdAt };
}
function serMsg(m) {
  const s = DB.users.get(m.senderId);
  return { ...m, sender: s ? serUser(s) : (m.senderId==='system'?{id:'system',displayName:'سیستم',color:'#5865F2'}:null) };
}
function roomsFor(uid) {
  return [...DB.rooms.values()].filter(r => r.isPublic || r.members.includes(uid)).map(serRoom);
}

// ══════════════════════════════════════════════════════════════
//  هندلر پیام
// ══════════════════════════════════════════════════════════════
function handle(c, raw) {
  let msg; try { msg = JSON.parse(raw); } catch { return; }
  const { type, payload = {} } = msg;
  const uid = c.userId;

  // ── register ──
  if (type === 'register') {
    const { username, password, displayName } = payload;
    if (!username || !password || username.length < 3)
      return wsSend(c, { t:'err', code:'INVALID', msg:'اطلاعات نامعتبر' });
    const uname = username.toLowerCase().trim();
    if (DB.byName.has(uname))
      return wsSend(c, { t:'err', code:'TAKEN', msg:'این نام کاربری قبلاً ثبت شده' });
    const user = mkUser(username, password, displayName);
    DB.users.set(user.id, user); DB.byName.set(user.username, user.id);
    DB.rooms.forEach(r => { if (r.isPublic) r.members.push(user.id); });
    const token = genToken();
    DB.sessions.set(token, user.id);
    c.userId = user.id; addClient(user.id, c);
    wsSend(c, { t:'registered', user:serUser(user,true), token, rooms:roomsFor(user.id) });
    bcastAll({ t:'online', list:onlineList() });
    return;
  }

  // ── login ──
  if (type === 'login') {
    const uid2 = DB.byName.get((payload.username||'').toLowerCase().trim());
    if (!uid2) return wsSend(c, { t:'err', code:'NOT_FOUND', msg:'کاربر یافت نشد' });
    const user = DB.users.get(uid2);
    if (hashPw(payload.password, user.salt) !== user.hash)
      return wsSend(c, { t:'err', code:'WRONG_PW', msg:'رمز عبور اشتباه' });
    const token = genToken();
    DB.sessions.set(token, user.id);
    c.userId = user.id; addClient(user.id, c);
    wsSend(c, { t:'logged_in', user:serUser(user,true), token, rooms:roomsFor(user.id) });
    bcastAll({ t:'online', list:onlineList() });
    return;
  }

  // ── auth ──
  if (type === 'auth') {
    const uid2 = DB.sessions.get(payload.token);
    if (!uid2) return wsSend(c, { t:'err', code:'BAD_TOKEN', msg:'نشست منقضی' });
    const user = DB.users.get(uid2);
    c.userId = user.id; addClient(user.id, c);
    wsSend(c, { t:'auth_ok', user:serUser(user,true), rooms:roomsFor(user.id) });
    bcastAll({ t:'online', list:onlineList() });
    return;
  }

  if (!uid) return wsSend(c, { t:'err', code:'UNAUTH' });

  switch (type) {

    case 'join': {
      const room = DB.rooms.get(payload.roomId);
      if (!room) return wsSend(c, { t:'err', msg:'اتاق یافت نشد' });
      if (!room.isPublic && !room.members.includes(uid))
        return wsSend(c, { t:'err', msg:'این اتاق خصوصی است' });
      if (!room.members.includes(uid)) room.members.push(uid);
      const msgs = (DB.msgs.get(room.id)||[]).slice(-60).map(serMsg);
      wsSend(c, { t:'joined', room:serRoom(room), msgs });
      const user = DB.users.get(uid);
      bcastRoom(room.id, { t:'member_joined', roomId:room.id, user:serUser(user,true) }, uid);
      break;
    }

    case 'join_invite': {
      const code = (payload.code||'').toUpperCase().trim();
      let found = null;
      DB.rooms.forEach(r => { if (r.inviteCode === code) found = r; });
      if (!found) return wsSend(c, { t:'err', msg:'کد دعوت نامعتبر' });
      if (!found.members.includes(uid)) found.members.push(uid);
      const msgs = (DB.msgs.get(found.id)||[]).slice(-60).map(serMsg);
      wsSend(c, { t:'joined', room:serRoom(found), msgs });
      const user = DB.users.get(uid);
      const sys = mkMsg('system', found.id, 'system', `👋 ${user.displayName} به اتاق پیوست`);
      DB.msgs.get(found.id).push(sys);
      found.lastMsg = { text:sys.content, senderId:'system', at:sys.createdAt };
      bcastRoom(found.id, { t:'msg', msg:serMsg(sys) });
      bcastAll({ t:'room_update', room:serRoom(found) });
      break;
    }

    case 'send': {
      const { roomId, msgType, content, replyToId } = payload;
      const room = DB.rooms.get(roomId);
      if (!room || !room.members.includes(uid))
        return wsSend(c, { t:'err', msg:'مجاز نیستید' });
      const msg = mkMsg(uid, roomId, msgType||'text', content, replyToId);
      DB.msgs.get(roomId).push(msg);
      room.lastMsg = {
        text: msgType==='text'?(typeof content==='string'?content.slice(0,50):''):`[${msgType}]`,
        senderId: uid, at: msg.createdAt,
      };
      bcastRoom(roomId, { t:'msg', msg:serMsg(msg) });
      bcastAll({ t:'room_update', room:serRoom(room) });
      break;
    }

    case 'get_msgs': {
      const { roomId, before, limit=60 } = payload;
      const room = DB.rooms.get(roomId); if (!room) break;
      let arr = DB.msgs.get(roomId)||[];
      if (before) { const idx=arr.findIndex(m=>m.id===before); arr=idx>0?arr.slice(Math.max(0,idx-limit),idx):[]; }
      else arr = arr.slice(-limit);
      wsSend(c, { t:'msgs_bulk', roomId, msgs:arr.map(serMsg) });
      break;
    }

    case 'edit': {
      const { roomId, msgId, text } = payload;
      const m = (DB.msgs.get(roomId)||[]).find(x=>x.id===msgId);
      if (!m || m.senderId!==uid || m.deleted) break;
      m.content = text; m.edited = true;
      bcastRoom(roomId, { t:'edited', roomId, msgId, text });
      break;
    }

    case 'delete': {
      const { roomId, msgId } = payload;
      const room = DB.rooms.get(roomId);
      const m = (DB.msgs.get(roomId)||[]).find(x=>x.id===msgId);
      if (!m) break;
      if (m.senderId!==uid && !room?.admins.includes(uid)) break;
      m.deleted=true; m.content='';
      bcastRoom(roomId, { t:'deleted', roomId, msgId });
      break;
    }

    case 'react': {
      const { roomId, msgId, emoji } = payload;
      const m = (DB.msgs.get(roomId)||[]).find(x=>x.id===msgId); if (!m) break;
      if (!m.reactions[emoji]) m.reactions[emoji]=[];
      const i = m.reactions[emoji].indexOf(uid);
      if (i===-1) m.reactions[emoji].push(uid);
      else { m.reactions[emoji].splice(i,1); if (!m.reactions[emoji].length) delete m.reactions[emoji]; }
      bcastRoom(roomId, { t:'reacted', roomId, msgId, reactions:m.reactions });
      break;
    }

    case 'pin': {
      const { roomId, msgId } = payload;
      const room = DB.rooms.get(roomId);
      if (!room || !room.admins.includes(uid)) break;
      room.pinnedMsgId = msgId;
      bcastRoom(roomId, { t:'pinned', roomId, msgId });
      break;
    }

    case 'typing': {
      const { roomId, on } = payload;
      const user = DB.users.get(uid);
      DB.rooms.get(roomId)?.members.forEach(mid => {
        if (mid !== uid) sendTo(mid, { t:'typing', roomId, userId:uid, name:user?.displayName, on });
      });
      break;
    }

    case 'create_room': {
      const { name, description, icon, category, isPublic } = payload;
      if (!name?.trim()) return wsSend(c, { t:'err', msg:'نام اتاق الزامی است' });
      const room = mkRoom(name, uid, { description, icon:icon||'💬', category:category||'عمومی', isPublic:isPublic!==false });
      DB.rooms.set(room.id, room); DB.msgs.set(room.id, []);
      const sys = mkMsg('system', room.id, 'system', `🎉 اتاق "${name}" ساخته شد`);
      DB.msgs.get(room.id).push(sys);
      room.lastMsg = { text:sys.content, senderId:'system', at:sys.createdAt };
      wsSend(c, { t:'room_created', room:serRoom(room) });
      if (room.isPublic) bcastAll({ t:'new_room', room:serRoom(room) });
      break;
    }

    case 'edit_room': {
      const { roomId, name, description } = payload;
      const room = DB.rooms.get(roomId);
      if (!room || !room.admins.includes(uid)) break;
      if (name) room.name = name.trim();
      if (description !== undefined) room.description = description.trim();
      bcastAll({ t:'room_update', room:serRoom(room) });
      break;
    }

    case 'delete_room': {
      const { roomId } = payload;
      const room = DB.rooms.get(roomId);
      if (!room || room.ownerId !== uid)
        return wsSend(c, { t:'err', msg:'فقط مالک می‌تواند اتاق را حذف کند' });
      bcastRoom(roomId, { t:'room_deleted', roomId });
      DB.rooms.delete(roomId); DB.msgs.delete(roomId);
      bcastAll({ t:'room_removed', roomId });
      break;
    }

    case 'leave_room': {
      const { roomId } = payload;
      const room = DB.rooms.get(roomId); if (!room) break;
      room.members = room.members.filter(m=>m!==uid);
      const user = DB.users.get(uid);
      const sys = mkMsg('system', roomId, 'system', `👋 ${user?.displayName} اتاق را ترک کرد`);
      DB.msgs.get(roomId)?.push(sys);
      bcastRoom(roomId, { t:'msg', msg:serMsg(sys) });
      bcastRoom(roomId, { t:'member_left', roomId, userId:uid });
      wsSend(c, { t:'left', roomId });
      break;
    }

    case 'get_members': {
      const { roomId } = payload;
      const room = DB.rooms.get(roomId); if (!room) break;
      const members = room.members.map(mid=>DB.users.get(mid)).filter(Boolean).map(u=>serUser(u));
      wsSend(c, { t:'members', roomId, members });
      break;
    }

    case 'kick': {
      const { roomId, targetId } = payload;
      const room = DB.rooms.get(roomId);
      if (!room || !room.admins.includes(uid)) break;
      room.members = room.members.filter(m=>m!==targetId);
      sendTo(targetId, { t:'kicked', roomId });
      bcastRoom(roomId, { t:'member_left', roomId, userId:targetId });
      break;
    }

    case 'promote': {
      const { roomId, targetId } = payload;
      const room = DB.rooms.get(roomId);
      if (!room || room.ownerId!==uid) break;
      if (!room.admins.includes(targetId)) room.admins.push(targetId);
      bcastRoom(roomId, { t:'room_update', room:serRoom(room) });
      break;
    }

    case 'regen_invite': {
      const { roomId } = payload;
      const room = DB.rooms.get(roomId);
      if (!room || !room.admins.includes(uid)) break;
      room.inviteCode = genCode();
      wsSend(c, { t:'invite_regen', roomId, code:room.inviteCode });
      break;
    }

    case 'search_rooms': {
      const q = (payload.q||'').toLowerCase().trim();
      const res = [...DB.rooms.values()]
        .filter(r => r.isPublic && (r.name.toLowerCase().includes(q)||r.description.toLowerCase().includes(q)))
        .map(serRoom);
      wsSend(c, { t:'search_res', rooms:res });
      break;
    }

    case 'update_profile': {
      const user = DB.users.get(uid); if (!user) break;
      if (payload.displayName) user.displayName = payload.displayName.trim();
      if (payload.bio !== undefined) user.bio = payload.bio.trim();
      if (payload.avatar !== undefined) user.avatar = payload.avatar;
      wsSend(c, { t:'profile_ok', user:serUser(user,true) });
      bcastAll({ t:'user_update', user:serUser(user,true) });
      break;
    }

    case 'mark_read': break; // future use
  }
}

// ══════════════════════════════════════════════════════════════
//  HTTP Server — سرو chatroom.html + WebSocket Upgrade
// ══════════════════════════════════════════════════════════════
const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  // سرو فایل HTML
  const filePath = path.join(__dirname, 'chatroom.html');
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('chatroom.html پیدا نشد');
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(data);
  });
});

// ── WebSocket Upgrade روی همان server ────────────────────────
server.on('upgrade', (req, socket, head) => {
  const headers = {};
  req.rawHeaders.forEach((v, i) => {
    if (i % 2 === 0) headers[v.toLowerCase()] = req.rawHeaders[i + 1];
  });

  if (!wsHandshake(socket, headers)) return;

  const c = { socket, userId: null };
  let buf = Buffer.alloc(0);

  // اگر داده‌ای در head بود
  if (head && head.length > 0) buf = Buffer.concat([buf, head]);

  socket.on('data', chunk => {
    buf = Buffer.concat([buf, chunk]);
    while (buf.length > 0) {
      const frame = parseFrame(buf);
      if (!frame) break;
      buf = buf.slice(frame.total);

      if (frame.op === 0x8) { socket.destroy(); break; }
      if (frame.op === 0x9) {
        const pong = Buffer.alloc(2); pong[0]=0x8A; pong[1]=0;
        if (socket.writable) socket.write(pong);
        continue;
      }
      if (frame.op === 0x1 || frame.op === 0x2) {
        try { handle(c, frame.payload.toString('utf8')); } catch (e) { console.error('ws handle:', e.message); }
      }
    }
  });

  socket.on('close', () => {
    const uid = c.userId; if (!uid) return;
    removeClient(uid, c);
    if (!clients.has(uid)) {
      const u = DB.users.get(uid);
      if (u) { u.status='offline'; u.lastSeen=now(); }
    }
    bcastAll({ t:'online', list:onlineList() });
  });

  socket.on('error', () => { try { socket.destroy(); } catch {} });
  socket.setTimeout(120000, () => { try { socket.destroy(); } catch {} });
});

// ── Start ──────────────────────────────────────────────────────
server.listen(PORT, '0.0.0.0', () => {
  const ips = getLocalIPs();
  console.log('');
  console.log('  ╔═══════════════════════════════════════════╗');
  console.log('  ║        💬  چت روم آماده است!              ║');
  console.log('  ╠═══════════════════════════════════════════╣');
  console.log(`  ║  💻 لپ‌تاپ:  http://localhost:${PORT}           ║`);
  ips.forEach(ip => console.log(`  ║  📱 گوشی:   http://${ip}:${PORT}   ║`));
  console.log('  ╠═══════════════════════════════════════════╣');
  console.log('  ║  HTTP + WebSocket روی همین پورت           ║');
  console.log('  ║  کاربران نمونه (رمز همه: 1234):           ║');
  console.log('  ║  ali  sara  reza  maryam  hasan           ║');
  console.log('  ╚═══════════════════════════════════════════╝');
  console.log('');
});
