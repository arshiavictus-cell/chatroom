// ══════════════════════════════════════════════════════════════
//  چت روم — سرور یکپارچه
//  HTTP + WebSocket روی یک پورت
//  Cloudinary برای فایل‌ها + WebRTC Signal برای صدا
//  اجرا: node chatroom-server.js
// ══════════════════════════════════════════════════════════════
'use strict';

const http   = require('http');
const https  = require('https');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const os     = require('os');
const { URLSearchParams } = require('url');

const PORT = parseInt(process.env.PORT || '3000', 10);

// ── Cloudinary Config (از env یا اینجا بنویس) ─────────────────
const CLOUD = {
  name:   process.env.CLOUDINARY_CLOUD_NAME   || '',
  key:    process.env.CLOUDINARY_API_KEY       || '',
  secret: process.env.CLOUDINARY_API_SECRET   || '',
};

// ── IP شبکه ───────────────────────────────────────────────────
function getLocalIPs() {
  const ips = [];
  Object.values(os.networkInterfaces()).forEach(list =>
    (list||[]).forEach(i => { if (i.family==='IPv4' && !i.internal) ips.push(i.address); })
  );
  return ips;
}

// ══════════════════════════════════════════════════════════════
//  Cloudinary Upload
// ══════════════════════════════════════════════════════════════
function cloudinaryUpload(base64Data, resourceType) {
  return new Promise((resolve, reject) => {
    if (!CLOUD.name || !CLOUD.key || !CLOUD.secret) {
      // بدون Cloudinary → همان base64 برگردان
      return resolve({ url: base64Data, public_id: null });
    }

    const timestamp = Math.floor(Date.now() / 1000).toString();
    const signStr   = `timestamp=${timestamp}${CLOUD.secret}`;
    const signature = crypto.createHash('sha1').update(signStr).digest('hex');

    // حذف prefix مثل "data:image/jpeg;base64,"
    const b64 = base64Data.replace(/^data:[^;]+;base64,/, '');
    const fileData = `data:${resourceType==='video'?'video/mp4':resourceType==='audio'?'audio/webm':'image/jpeg'};base64,${b64}`;

    const body = new URLSearchParams({
      file:          fileData,
      upload_preset: 'ml_default',
      timestamp,
      api_key:       CLOUD.key,
      signature,
      resource_type: resourceType || 'auto',
    }).toString();

    const url = `https://api.cloudinary.com/v1_1/${CLOUD.name}/${resourceType||'auto'}/upload`;
    const req = https.request(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) },
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { reject(new Error('Cloudinary parse error')); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ══════════════════════════════════════════════════════════════
//  WebSocket دستی
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
  if (masked) { const mk = buf.slice(moff, moff+4); for (let i=0;i<p.length;i++) p[i]^=mk[i%4]; }
  return { op: buf[0] & 0x0f, payload: p, total: off+len };
}

function makeFrame(data) {
  const p = Buffer.from(data, 'utf8'), l = p.length;
  let h;
  if (l < 126)        { h=Buffer.alloc(2);  h[0]=0x81; h[1]=l; }
  else if (l < 65536) { h=Buffer.alloc(4);  h[0]=0x81; h[1]=126; h.writeUInt16BE(l,2); }
  else                { h=Buffer.alloc(10); h[0]=0x81; h[1]=127; h.writeBigUInt64BE(BigInt(l),2); }
  return Buffer.concat([h,p]);
}

function wsSend(c, obj) {
  if (!c?.socket?.writable) return;
  try { c.socket.write(makeFrame(typeof obj==='string'?obj:JSON.stringify(obj))); } catch {}
}

// ══════════════════════════════════════════════════════════════
//  ابزار
// ══════════════════════════════════════════════════════════════
let _seq = 1;
const genId    = p => (p||'') + (_seq++) + '_' + crypto.randomBytes(3).toString('hex');
const genToken = ()  => crypto.randomBytes(28).toString('hex');
const genCode  = ()  => crypto.randomBytes(4).toString('hex').toUpperCase();
const hashPw   = (pw, salt) => crypto.pbkdf2Sync(pw, salt, 10000, 32, 'sha256').toString('hex');
const now      = ()  => Date.now();
const COLORS   = ['#5865F2','#EB459E','#57F287','#FEE75C','#ED4245','#3498db','#9b59b6','#e67e22','#1abc9c','#e74c3c'];
const avColor  = n => COLORS[Math.abs((n||'X').charCodeAt(0))%COLORS.length];

// ══════════════════════════════════════════════════════════════
//  دیتابیس
// ══════════════════════════════════════════════════════════════
const DB = {
  users:    new Map(),
  byName:   new Map(),
  sessions: new Map(),
  rooms:    new Map(),
  msgs:     new Map(),
  // کانال‌های صوتی: roomId → Map<userId, {c, stream}>
  voiceChannels: new Map(),
};

function mkUser(username, password, displayName) {
  const id = genId('u'), salt = crypto.randomBytes(16).toString('hex');
  return { id, username:username.toLowerCase().trim(),
    displayName:(displayName||username).trim(),
    avatar:null, color:avColor(displayName||username),
    hash:hashPw(password,salt), salt, bio:'',
    createdAt:now(), status:'offline', lastSeen:now() };
}
function mkRoom(name, ownerId, opts={}) {
  const id = genId('r');
  return { id, name:name.trim(), description:(opts.description||'').trim(),
    icon:opts.icon||'💬', category:opts.category||'عمومی',
    ownerId, admins:[ownerId], members:[ownerId],
    isPublic:opts.isPublic!==false,
    inviteCode:genCode(), createdAt:now(),
    lastMsg:null, pinnedMsgId:null,
    hasVoice:true };   // هر اتاق یه کانال صوتی هم داره
}
function mkMsg(senderId, roomId, type, content, replyToId) {
  return { id:genId('m'), senderId, roomId, type, content,
    replyToId:replyToId||null, reactions:{},
    edited:false, deleted:false, createdAt:now() };
}

// ── Seed ───────────────────────────────────────────────────────
;(function seed() {
  [{un:'ali',pw:'1234',dn:'علی رضایی'},{un:'sara',pw:'1234',dn:'سارا احمدی'},
   {un:'reza',pw:'1234',dn:'رضا کریمی'},{un:'maryam',pw:'1234',dn:'مریم موسوی'},
   {un:'hasan',pw:'1234',dn:'حسن نجفی'}].forEach(x => {
    const u=mkUser(x.un,x.pw,x.dn); DB.users.set(u.id,u); DB.byName.set(u.username,u.id);
  });
  const aliId=DB.byName.get('ali');
  [{name:'عمومی',icon:'🌍',cat:'عمومی',desc:'گفتگوی عمومی'},
   {name:'برنامه‌نویسی',icon:'💻',cat:'تکنولوژی',desc:'کد و تکنولوژی'},
   {name:'گیمینگ',icon:'🎮',cat:'سرگرمی',desc:'دنیای بازی'},
   {name:'موسیقی',icon:'🎵',cat:'هنر',desc:'موسیقی و هنر'},
   {name:'فیلم و سریال',icon:'🎬',cat:'سرگرمی',desc:'سینما و سریال'},
   {name:'ورزش',icon:'⚽',cat:'ورزش',desc:'دنیای ورزش'}].forEach(rd => {
    const room=mkRoom(rd.name,aliId,{description:rd.desc,icon:rd.icon,category:rd.cat,isPublic:true});
    DB.users.forEach(u => { if(!room.members.includes(u.id)) room.members.push(u.id); });
    DB.rooms.set(room.id,room); DB.msgs.set(room.id,[]);
    DB.voiceChannels.set(room.id, new Map());
    const sys=mkMsg('system',room.id,'system',`🎉 به اتاق ${rd.name} خوش آمدید!`);
    DB.msgs.get(room.id).push(sys);
    room.lastMsg={text:sys.content,senderId:'system',at:sys.createdAt};
  });
  console.log('✅ داده‌های اولیه آماده شد');
})();

// ══════════════════════════════════════════════════════════════
//  کلاینت‌های فعال
// ══════════════════════════════════════════════════════════════
const clients = new Map(); // userId → Set<clientObj>

function addClient(uid,c)    { if(!clients.has(uid)) clients.set(uid,new Set()); clients.get(uid).add(c); }
function removeClient(uid,c) { const s=clients.get(uid); if(s){s.delete(c);if(!s.size)clients.delete(uid);} }
function sendTo(uid,data)    { clients.get(uid)?.forEach(c=>wsSend(c,data)); }
function bcastRoom(rid,data,skip) { DB.rooms.get(rid)?.members.forEach(uid=>{if(uid!==skip)sendTo(uid,data);}); }
function bcastAll(data)      { clients.forEach(set=>set.forEach(c=>wsSend(c,data))); }
function onlineInRoom(rid)   { return (DB.rooms.get(rid)?.members||[]).filter(uid=>clients.has(uid)).length; }
function onlineList()        { return [...clients.keys()]; }

// ══════════════════════════════════════════════════════════════
//  Serializers
// ══════════════════════════════════════════════════════════════
function serUser(u,force) {
  return {id:u.id,username:u.username,displayName:u.displayName,
    avatar:u.avatar,color:u.color,bio:u.bio,
    status:(force||clients.has(u.id))?'online':'offline',lastSeen:u.lastSeen};
}
function serRoom(r) {
  // اعضای صوتی این اتاق
  const vc = DB.voiceChannels.get(r.id);
  const voiceUsers = vc ? [...vc.keys()] : [];
  return {id:r.id,name:r.name,description:r.description,icon:r.icon,
    category:r.category,ownerId:r.ownerId,admins:r.admins,
    memberCount:r.members.length,onlineCount:onlineInRoom(r.id),
    isPublic:r.isPublic,inviteCode:r.inviteCode,
    lastMsg:r.lastMsg,pinnedMsgId:r.pinnedMsgId,createdAt:r.createdAt,
    hasVoice:true, voiceUsers};
}
function serMsg(m) {
  const s=DB.users.get(m.senderId);
  return {...m, sender:s?serUser(s):(m.senderId==='system'?{id:'system',displayName:'سیستم',color:'#5865F2'}:null)};
}
function roomsFor(uid) {
  return [...DB.rooms.values()].filter(r=>r.isPublic||r.members.includes(uid)).map(serRoom);
}

// ══════════════════════════════════════════════════════════════
//  هندلر پیام WebSocket
// ══════════════════════════════════════════════════════════════
async function handle(c, raw) {
  let msg; try { msg=JSON.parse(raw); } catch { return; }
  const {type,payload={}} = msg;
  const uid = c.userId;

  // ── register ──────────────────────────────────────────────
  if (type==='register') {
    const {username,password,displayName}=payload;
    if (!username||!password||username.length<3)
      return wsSend(c,{t:'err',code:'INVALID',msg:'اطلاعات نامعتبر'});
    const uname=username.toLowerCase().trim();
    if (DB.byName.has(uname))
      return wsSend(c,{t:'err',code:'TAKEN',msg:'این نام کاربری ثبت شده'});
    const user=mkUser(username,password,displayName);
    DB.users.set(user.id,user); DB.byName.set(user.username,user.id);
    DB.rooms.forEach(r=>{ if(r.isPublic) r.members.push(user.id); });
    const token=genToken(); DB.sessions.set(token,user.id);
    c.userId=user.id; addClient(user.id,c);
    wsSend(c,{t:'registered',user:serUser(user,true),token,rooms:roomsFor(user.id)});
    bcastAll({t:'online',list:onlineList()});
    return;
  }

  // ── login ─────────────────────────────────────────────────
  if (type==='login') {
    const uid2=DB.byName.get((payload.username||'').toLowerCase().trim());
    if (!uid2) return wsSend(c,{t:'err',code:'NOT_FOUND',msg:'کاربر یافت نشد'});
    const user=DB.users.get(uid2);
    if (hashPw(payload.password,user.salt)!==user.hash)
      return wsSend(c,{t:'err',code:'WRONG_PW',msg:'رمز عبور اشتباه'});
    const token=genToken(); DB.sessions.set(token,user.id);
    c.userId=user.id; addClient(user.id,c);
    wsSend(c,{t:'logged_in',user:serUser(user,true),token,rooms:roomsFor(user.id)});
    bcastAll({t:'online',list:onlineList()});
    return;
  }

  // ── auth ──────────────────────────────────────────────────
  if (type==='auth') {
    const uid2=DB.sessions.get(payload.token);
    if (!uid2) return wsSend(c,{t:'err',code:'BAD_TOKEN',msg:'نشست منقضی'});
    const user=DB.users.get(uid2);
    c.userId=user.id; addClient(user.id,c);
    wsSend(c,{t:'auth_ok',user:serUser(user,true),rooms:roomsFor(user.id)});
    bcastAll({t:'online',list:onlineList()});
    return;
  }

  if (!uid) return wsSend(c,{t:'err',code:'UNAUTH'});

  switch(type) {

    // ── join room ──────────────────────────────────────────
    case 'join': {
      const room=DB.rooms.get(payload.roomId);
      if (!room) return wsSend(c,{t:'err',msg:'اتاق یافت نشد'});
      if (!room.isPublic&&!room.members.includes(uid))
        return wsSend(c,{t:'err',msg:'این اتاق خصوصی است'});
      if (!room.members.includes(uid)) room.members.push(uid);
      const msgs=(DB.msgs.get(room.id)||[]).slice(-60).map(serMsg);
      // اعضای صوتی فعلی
      const vc=DB.voiceChannels.get(room.id)||new Map();
      const voiceMembers=[...vc.keys()].map(vid=>{
        const vu=DB.users.get(vid); return vu?serUser(vu):null;
      }).filter(Boolean);
      wsSend(c,{t:'joined',room:serRoom(room),msgs,voiceMembers});
      bcastRoom(room.id,{t:'member_joined',roomId:room.id,user:serUser(DB.users.get(uid),true)},uid);
      break;
    }

    // ── join invite ────────────────────────────────────────
    case 'join_invite': {
      const code=(payload.code||'').toUpperCase().trim();
      let found=null; DB.rooms.forEach(r=>{if(r.inviteCode===code)found=r;});
      if (!found) return wsSend(c,{t:'err',msg:'کد دعوت نامعتبر'});
      if (!found.members.includes(uid)) found.members.push(uid);
      const msgs=(DB.msgs.get(found.id)||[]).slice(-60).map(serMsg);
      wsSend(c,{t:'joined',room:serRoom(found),msgs,voiceMembers:[]});
      const user=DB.users.get(uid);
      const sys=mkMsg('system',found.id,'system',`👋 ${user.displayName} به اتاق پیوست`);
      DB.msgs.get(found.id).push(sys);
      found.lastMsg={text:sys.content,senderId:'system',at:sys.createdAt};
      bcastRoom(found.id,{t:'msg',msg:serMsg(sys)});
      bcastAll({t:'room_update',room:serRoom(found)});
      break;
    }

    // ── send message (text) ────────────────────────────────
    case 'send': {
      const {roomId,msgType,content,replyToId}=payload;
      const room=DB.rooms.get(roomId);
      if (!room||!room.members.includes(uid))
        return wsSend(c,{t:'err',msg:'مجاز نیستید'});
      const msg=mkMsg(uid,roomId,msgType||'text',content,replyToId);
      DB.msgs.get(roomId).push(msg);
      const previewText=msgType==='text'?(typeof content==='string'?content.slice(0,50):''):`[${msgType}]`;
      room.lastMsg={text:previewText,senderId:uid,at:msg.createdAt};
      bcastRoom(roomId,{t:'msg',msg:serMsg(msg)});
      bcastAll({t:'room_update',room:serRoom(room)});
      break;
    }

    // ── upload file/image/audio → Cloudinary ──────────────
    case 'upload': {
      const {roomId,fileType,base64,fileName,replyToId,duration}=payload;
      const room=DB.rooms.get(roomId);
      if (!room||!room.members.includes(uid))
        return wsSend(c,{t:'err',msg:'مجاز نیستید'});

      // نوع resource برای Cloudinary
      const resType = fileType==='image'?'image':
                      fileType==='audio'?'video':  // Cloudinary audio را video می‌خواند
                      fileType==='video'?'video':'auto';
      try {
        const result = await cloudinaryUpload(base64, resType);
        const url = result.secure_url || result.url || base64;

        const content = fileType==='audio'
          ? {url, fileName:fileName||'audio.webm', duration:duration||0, publicId:result.public_id}
          : fileType==='image'
            ? {url, fileName:fileName||'image', publicId:result.public_id}
            : {url, fileName:fileName||'file', publicId:result.public_id};

        const msg=mkMsg(uid,roomId,fileType,content,replyToId||null);
        DB.msgs.get(roomId).push(msg);
        room.lastMsg={text:fileType==='image'?'🖼 عکس':fileType==='audio'?'🎤 پیام صوتی':'📎 فایل',senderId:uid,at:msg.createdAt};
        bcastRoom(roomId,{t:'msg',msg:serMsg(msg)});
        bcastAll({t:'room_update',room:serRoom(room)});
        wsSend(c,{t:'upload_ok',msgId:msg.id});
      } catch(e) {
        console.error('upload error:', e.message);
        wsSend(c,{t:'err',msg:'آپلود ناموفق: '+e.message});
      }
      break;
    }

    // ── get messages ───────────────────────────────────────
    case 'get_msgs': {
      const {roomId,before,limit=60}=payload;
      const room=DB.rooms.get(roomId); if(!room) break;
      let arr=DB.msgs.get(roomId)||[];
      if (before){const idx=arr.findIndex(m=>m.id===before);arr=idx>0?arr.slice(Math.max(0,idx-limit),idx):[];}
      else arr=arr.slice(-limit);
      wsSend(c,{t:'msgs_bulk',roomId,msgs:arr.map(serMsg)});
      break;
    }

    case 'edit': {
      const {roomId,msgId,text}=payload;
      const m=(DB.msgs.get(roomId)||[]).find(x=>x.id===msgId);
      if (!m||m.senderId!==uid||m.deleted) break;
      m.content=text; m.edited=true;
      bcastRoom(roomId,{t:'edited',roomId,msgId,text});
      break;
    }

    case 'delete': {
      const {roomId,msgId}=payload;
      const room=DB.rooms.get(roomId);
      const m=(DB.msgs.get(roomId)||[]).find(x=>x.id===msgId);
      if (!m) break;
      if (m.senderId!==uid&&!room?.admins.includes(uid)) break;
      m.deleted=true; m.content='';
      bcastRoom(roomId,{t:'deleted',roomId,msgId});
      break;
    }

    case 'react': {
      const {roomId,msgId,emoji}=payload;
      const m=(DB.msgs.get(roomId)||[]).find(x=>x.id===msgId); if(!m) break;
      if (!m.reactions[emoji]) m.reactions[emoji]=[];
      const i=m.reactions[emoji].indexOf(uid);
      if (i===-1) m.reactions[emoji].push(uid);
      else{m.reactions[emoji].splice(i,1);if(!m.reactions[emoji].length)delete m.reactions[emoji];}
      bcastRoom(roomId,{t:'reacted',roomId,msgId,reactions:m.reactions});
      break;
    }

    case 'pin': {
      const {roomId,msgId}=payload;
      const room=DB.rooms.get(roomId);
      if (!room||!room.admins.includes(uid)) break;
      room.pinnedMsgId=msgId;
      bcastRoom(roomId,{t:'pinned',roomId,msgId});
      break;
    }

    case 'typing': {
      const {roomId,on}=payload;
      const user=DB.users.get(uid);
      DB.rooms.get(roomId)?.members.forEach(mid=>{
        if(mid!==uid) sendTo(mid,{t:'typing',roomId,userId:uid,name:user?.displayName,on});
      });
      break;
    }

    // ── voice channel ──────────────────────────────────────
    // پیوستن به کانال صوتی
    case 'voice_join': {
      const {roomId}=payload;
      const room=DB.rooms.get(roomId);
      if (!room||!room.members.includes(uid)) break;
      if (!DB.voiceChannels.has(roomId)) DB.voiceChannels.set(roomId,new Map());
      const vc=DB.voiceChannels.get(roomId);
      vc.set(uid,{c});
      // اطلاع به بقیه اعضای صوتی
      const user=DB.users.get(uid);
      bcastRoom(roomId,{t:'voice_joined',roomId,user:serUser(user,true)},uid);
      // لیست کسانی که الان داخل کانال هستند
      const currentVoice=[...vc.keys()].filter(vid=>vid!==uid).map(vid=>{
        const vu=DB.users.get(vid); return vu?serUser(vu):null;
      }).filter(Boolean);
      wsSend(c,{t:'voice_joined_ok',roomId,currentVoice});
      break;
    }

    // خروج از کانال صوتی
    case 'voice_leave': {
      const {roomId}=payload;
      const vc=DB.voiceChannels.get(roomId);
      if (vc) { vc.delete(uid); }
      bcastRoom(roomId,{t:'voice_left',roomId,userId:uid});
      break;
    }

    // WebRTC Signaling — offer
    case 'voice_offer': {
      const {roomId,targetId,offer}=payload;
      sendTo(targetId,{t:'voice_offer',roomId,fromId:uid,offer});
      break;
    }

    // WebRTC Signaling — answer
    case 'voice_answer': {
      const {roomId,targetId,answer}=payload;
      sendTo(targetId,{t:'voice_answer',roomId,fromId:uid,answer});
      break;
    }

    // WebRTC Signaling — ICE candidate
    case 'voice_ice': {
      const {roomId,targetId,candidate}=payload;
      sendTo(targetId,{t:'voice_ice',roomId,fromId:uid,candidate});
      break;
    }

    // Mute/Unmute broadcast
    case 'voice_mute': {
      const {roomId,muted}=payload;
      bcastRoom(roomId,{t:'voice_mute',roomId,userId:uid,muted});
      break;
    }

    // ── room management ────────────────────────────────────
    case 'create_room': {
      const {name,description,icon,category,isPublic}=payload;
      if (!name?.trim()) return wsSend(c,{t:'err',msg:'نام اتاق الزامی است'});
      const room=mkRoom(name,uid,{description,icon:icon||'💬',category:category||'عمومی',isPublic:isPublic!==false});
      DB.rooms.set(room.id,room); DB.msgs.set(room.id,[]); DB.voiceChannels.set(room.id,new Map());
      const sys=mkMsg('system',room.id,'system',`🎉 اتاق "${name}" ساخته شد`);
      DB.msgs.get(room.id).push(sys);
      room.lastMsg={text:sys.content,senderId:'system',at:sys.createdAt};
      wsSend(c,{t:'room_created',room:serRoom(room)});
      if(room.isPublic) bcastAll({t:'new_room',room:serRoom(room)});
      break;
    }

    case 'edit_room': {
      const {roomId,name,description}=payload;
      const room=DB.rooms.get(roomId);
      if (!room||!room.admins.includes(uid)) break;
      if (name) room.name=name.trim();
      if (description!==undefined) room.description=description.trim();
      bcastAll({t:'room_update',room:serRoom(room)});
      break;
    }

    case 'delete_room': {
      const {roomId}=payload;
      const room=DB.rooms.get(roomId);
      if (!room||room.ownerId!==uid)
        return wsSend(c,{t:'err',msg:'فقط مالک می‌تواند اتاق را حذف کند'});
      bcastRoom(roomId,{t:'room_deleted',roomId});
      DB.rooms.delete(roomId); DB.msgs.delete(roomId); DB.voiceChannels.delete(roomId);
      bcastAll({t:'room_removed',roomId});
      break;
    }

    case 'leave_room': {
      const {roomId}=payload;
      const room=DB.rooms.get(roomId); if(!room) break;
      room.members=room.members.filter(m=>m!==uid);
      DB.voiceChannels.get(roomId)?.delete(uid);
      const user=DB.users.get(uid);
      const sys=mkMsg('system',roomId,'system',`👋 ${user?.displayName} اتاق را ترک کرد`);
      DB.msgs.get(roomId)?.push(sys);
      bcastRoom(roomId,{t:'msg',msg:serMsg(sys)});
      bcastRoom(roomId,{t:'member_left',roomId,userId:uid});
      wsSend(c,{t:'left',roomId});
      break;
    }

    case 'get_members': {
      const {roomId}=payload;
      const room=DB.rooms.get(roomId); if(!room) break;
      const members=room.members.map(mid=>DB.users.get(mid)).filter(Boolean).map(u=>serUser(u));
      wsSend(c,{t:'members',roomId,members});
      break;
    }

    case 'kick': {
      const {roomId,targetId}=payload;
      const room=DB.rooms.get(roomId);
      if (!room||!room.admins.includes(uid)) break;
      room.members=room.members.filter(m=>m!==targetId);
      DB.voiceChannels.get(roomId)?.delete(targetId);
      sendTo(targetId,{t:'kicked',roomId});
      bcastRoom(roomId,{t:'member_left',roomId,userId:targetId});
      break;
    }

    case 'promote': {
      const {roomId,targetId}=payload;
      const room=DB.rooms.get(roomId);
      if (!room||room.ownerId!==uid) break;
      if (!room.admins.includes(targetId)) room.admins.push(targetId);
      bcastRoom(roomId,{t:'room_update',room:serRoom(room)});
      break;
    }

    case 'regen_invite': {
      const {roomId}=payload;
      const room=DB.rooms.get(roomId);
      if (!room||!room.admins.includes(uid)) break;
      room.inviteCode=genCode();
      wsSend(c,{t:'invite_regen',roomId,code:room.inviteCode});
      break;
    }

    case 'search_rooms': {
      const q=(payload.q||'').toLowerCase().trim();
      const res=[...DB.rooms.values()]
        .filter(r=>r.isPublic&&(r.name.toLowerCase().includes(q)||r.description.toLowerCase().includes(q)))
        .map(serRoom);
      wsSend(c,{t:'search_res',rooms:res});
      break;
    }

    case 'update_profile': {
      const user=DB.users.get(uid); if(!user) break;
      if (payload.displayName) user.displayName=payload.displayName.trim();
      if (payload.bio!==undefined) user.bio=payload.bio.trim();
      if (payload.avatar!==undefined) user.avatar=payload.avatar;
      wsSend(c,{t:'profile_ok',user:serUser(user,true)});
      bcastAll({t:'user_update',user:serUser(user,true)});
      break;
    }

    case 'mark_read': break;
  }
}

// ══════════════════════════════════════════════════════════════
//  HTTP + WebSocket Upgrade روی یک پورت
// ══════════════════════════════════════════════════════════════
const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  const filePath = path.join(__dirname, 'chatroom.html');
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('chatroom.html not found'); return; }
    res.writeHead(200, { 'Content-Type':'text/html;charset=utf-8' });
    res.end(data);
  });
});

server.on('upgrade', (req, socket, head) => {
  const headers = {};
  req.rawHeaders.forEach((v,i) => { if(i%2===0) headers[v.toLowerCase()]=req.rawHeaders[i+1]; });
  if (!wsHandshake(socket, headers)) return;

  const c = { socket, userId:null };
  let buf = head && head.length > 0 ? Buffer.from(head) : Buffer.alloc(0);

  socket.on('data', chunk => {
    buf = Buffer.concat([buf, chunk]);
    while (buf.length > 0) {
      const frame = parseFrame(buf); if (!frame) break;
      buf = buf.slice(frame.total);
      if (frame.op===0x8) { socket.destroy(); break; }
      if (frame.op===0x9) { const p=Buffer.alloc(2);p[0]=0x8A;p[1]=0; if(socket.writable)socket.write(p); continue; }
      if (frame.op===0x1||frame.op===0x2) {
        handle(c, frame.payload.toString('utf8')).catch(e=>console.error('handle async error:',e.message));
      }
    }
  });

  socket.on('close', () => {
    const uid=c.userId; if(!uid) return;
    // خروج از همه کانال‌های صوتی
    DB.voiceChannels.forEach((vc,roomId)=>{
      if (vc.has(uid)) { vc.delete(uid); bcastRoom(roomId,{t:'voice_left',roomId,userId:uid}); }
    });
    removeClient(uid,c);
    if (!clients.has(uid)) { const u=DB.users.get(uid); if(u){u.status='offline';u.lastSeen=now();} }
    bcastAll({t:'online',list:onlineList()});
  });

  socket.on('error', ()=>{ try{socket.destroy();}catch{} });
  socket.setTimeout(180000, ()=>{ try{socket.destroy();}catch{} });
});

server.listen(PORT, '0.0.0.0', () => {
  const ips=getLocalIPs();
  const hasCloud=!!(CLOUD.name&&CLOUD.key&&CLOUD.secret);
  console.log('');
  console.log('  ╔══════════════════════════════════════════════╗');
  console.log('  ║         💬  چت روم آماده است!                ║');
  console.log('  ╠══════════════════════════════════════════════╣');
  console.log(`  ║  💻 لپ‌تاپ:  http://localhost:${PORT}             ║`);
  ips.forEach(ip=>console.log(`  ║  📱 گوشی:   http://${ip}:${PORT}   ║`));
  console.log('  ╠══════════════════════════════════════════════╣');
  console.log(`  ║  ☁️  Cloudinary: ${hasCloud?'✅ فعال':'❌ غیرفعال (base64 fallback)'}    ║`);
  console.log('  ║  🎙️ گفتگوی صوتی گروهی: ✅ فعال              ║');
  console.log('  ║  کاربران نمونه (رمز همه: 1234):              ║');
  console.log('  ║  ali · sara · reza · maryam · hasan          ║');
  console.log('  ╚══════════════════════════════════════════════╝');
  if (!hasCloud) {
    console.log('');
    console.log('  ⚠️  برای Cloudinary متغیرهای محیطی رو ست کن:');
    console.log('     CLOUDINARY_CLOUD_NAME=xxx');
    console.log('     CLOUDINARY_API_KEY=xxx');
    console.log('     CLOUDINARY_API_SECRET=xxx');
  }
  console.log('');
});
