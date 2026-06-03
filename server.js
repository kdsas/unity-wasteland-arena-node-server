const http = require("http");

const { WebSocketServer } = require("ws");

const sqlite3 = require("sqlite3").verbose();

const crypto = require("crypto");

const path = require("path");

const fs = require("fs");



// ================= CONFIG =================

const BACKUP_DIR = "./backups";

if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR);



// ================= HELPERS =================

function makeSecret() {

return crypto.randomBytes(32).toString("hex");

}

function sign(data, secret) {

return crypto.createHmac("sha256", secret).update(data).digest("base64");

}

function sha(s) {

return crypto.createHash("sha256").update(s).digest("hex");

}

function normalizePair(a, b){

return a < b ? [a, b] : [b, a];

}



function broadcastPresence(username, online, state){

wss.clients.forEach(c=>{

if(c.readyState === 1){

c.send(JSON.stringify({

type: "PRESENCE_UPDATE",

username,

online,

state

}));

}

});

}



// ================= SQLITE =================

const db = new sqlite3.Database(path.join(__dirname, "users.db"));



db.serialize(() => {

db.run(`CREATE TABLE IF NOT EXISTS users (

username TEXT PRIMARY KEY,

password_hash TEXT,

secret TEXT,

cheat_flags INTEGER DEFAULT 0,

last_stats_hash TEXT,

device TEXT

)`);



db.run(`CREATE TABLE IF NOT EXISTS player_stats (

username TEXT PRIMARY KEY,

json TEXT

)`);



db.run(`CREATE TABLE IF NOT EXISTS hwid_bans (

hwid TEXT PRIMARY KEY,

reason TEXT,

created_at INTEGER

)`);



// 🔒 Safe tables

db.run(`CREATE TABLE IF NOT EXISTS friends (

user1 TEXT,

user2 TEXT,

created_at INTEGER,

UNIQUE(user1,user2)

)`);



db.run(`CREATE TABLE IF NOT EXISTS friend_requests (

from_user TEXT,

to_user TEXT,

created_at INTEGER,

UNIQUE(from_user,to_user)

)`);



db.run(`CREATE TABLE IF NOT EXISTS blocks (

blocker TEXT,

blocked TEXT,

created_at INTEGER,

UNIQUE(blocker,blocked)

)`);

});



// ================= HELPERS =================

function isBlocked(a,b,cb){

db.get(

`SELECT 1 FROM blocks WHERE (blocker=? AND blocked=?) OR (blocker=? AND blocked=?)`,

[a,b,b,a],

(e,row)=>cb(!!row)

);

}



// ================= HWID =================

function banHWID(hwid, reason){

db.run("INSERT OR IGNORE INTO hwid_bans VALUES(?,?,?)",[hwid,reason,Date.now()]);

}



function isHWIDBanned(hwid, cb){

db.get("SELECT reason FROM hwid_bans WHERE hwid=?", [hwid], (e,row)=>{

cb(row ? row.reason : null);

});

}



// ================= CHEAT =================

function isImpossible(oldS, newS) {

if (!oldS || !oldS.kills) return false;

if (newS.kills - oldS.kills > 50) return true;

if (newS.bossKills - oldS.bossKills > 3) return true;

if (newS.xp - oldS.xp > 10000) return true;

if (newS.timeSurvived - oldS.timeSurvived > 3600) return true;

return false;

}



function flag(username, reason){

console.log("🚨 CHEAT:", username, reason);



db.get("SELECT device FROM users WHERE username=?", [username], (e,row)=>{

if(row?.device){

if(reason === "IMPOSSIBLE_PROGRESS" || reason === "BAD_SIGNATURE"){

banHWID(row.device, "Cheating");

}

}

});



db.run("UPDATE users SET cheat_flags = cheat_flags + 1 WHERE username=?", [username]);

}



// ================= TIER =================

function computeTier(stats){

if(stats.bossKills >= 25) return 7;

if(stats.bossKills >= 18) return 6;

if(stats.bossKills >= 12) return 5;

if(stats.bossKills >= 8) return 4;

if(stats.bossKills >= 5) return 3;

if(stats.bossKills >= 3) return 2;

return 1;

}



// ================= HTTP =================

const server = http.createServer((req,res)=>{

res.writeHead(200);

res.end("Auth server online");

});



// ================= WEBSOCKET =================

const wss = new WebSocketServer({ server });



wss.on("connection", (ws)=>{



ws.on("message", (msg)=>{

let data;

try {

data = JSON.parse(msg.toString());

} catch {

return;

}



const { type, username, password_hash, json, sig, secret, device } = data;



if(!type || !username) return;



// ===== SECURITY =====

if(type !== "REGISTER" && type !== "LOGIN"){

if(!secret) return;

if(sign(username, secret) !== sig){

flag(username,"BAD_SIGNATURE");

return;

}

}

if(type === "PRESENCE_SET"){

ws.presence = data.state || "online";

ws.username = username;



broadcastPresence(username, true, ws.presence);



return;

}

if(type === "CHAT"){

const { message, channel, target, msgId } = data;



if(!message || message.length > 200) return;



// spam throttle

if(!ws.lastChat) ws.lastChat = 0;

if(Date.now() - ws.lastChat < 200) return;

ws.lastChat = Date.now();



const payload = JSON.stringify({

type: "CHAT_RESP",

username,

message,

channel,

target,

msgId,

serverTime: Date.now()

});



// 🔥 BROADCAST (THIS WAS MISSING)

wss.clients.forEach(client => {

if (client.readyState === 1) {

client.send(payload);

}

});

}

// ================= REGISTER =================

if(type === "REGISTER"){

const s = makeSecret();

db.run(

"INSERT INTO users(username,password_hash,secret,device) VALUES(?,?,?,?)",

[username,password_hash,s,device],

err=>{

if(err){

ws.send(JSON.stringify({ type:"REGISTER_RESP", success:false }));

} else {

ws.send(JSON.stringify({ type:"REGISTER_RESP", success:true, secret:s }));

}

}

);

return;

}



// ================= LOGIN =================

if(type === "LOGIN"){

isHWIDBanned(device, (reason)=>{

if(reason){

ws.send(JSON.stringify({

type:"LOGIN_RESP",

success:false,

message:"HWID BANNED: " + reason

}));

return;

}



db.get(

"SELECT password_hash, secret, cheat_flags, device FROM users WHERE username=?",

[username],

(e,row)=>{

if(!row || row.password_hash !== password_hash){

ws.send(JSON.stringify({ type:"LOGIN_RESP", success:false }));

return;

}



if(row.cheat_flags >= 3){

ws.send(JSON.stringify({ type:"LOGIN_RESP", success:false, message:"Account banned" }));

return;

}



if(!row.device){

db.run("UPDATE users SET device=? WHERE username=?", [device, username]);

}

else if(row.device !== device){

banHWID(device, "Account sharing / evasion");

ws.send(JSON.stringify({ type:"LOGIN_RESP", success:false, message:"Account locked" }));

return;

}



ws.send(JSON.stringify({

type:"LOGIN_RESP",

success:true,

secret: row.secret,

flags: row.cheat_flags

}));

}

);

});

return;

}



// ================= FRIEND SYSTEM =================

if(type === "FRIEND_REQUEST"){

const target = data.target;

if(!target || username === target) return;



isBlocked(username, target, (blocked)=>{

if(blocked) return;



const [u1,u2] = normalizePair(username, target);



db.get(

"SELECT 1 FROM friends WHERE user1=? AND user2=?",

[u1,u2],

(e,row)=>{

if(row) return;



db.run(

"INSERT OR IGNORE INTO friend_requests VALUES(?,?,?)",

[username, target, Date.now()]

);

}

);

});

return;

}



if(type === "FRIEND_WITHDRAW"){

db.run(

"DELETE FROM friend_requests WHERE from_user=? AND to_user=?",

[username, data.target]

);

return;

}



if(type === "FRIEND_ACCEPT"){

const target = data.target;

if(!target || username === target) return;



const [u1,u2] = normalizePair(username, target);



db.get(

"SELECT 1 FROM friend_requests WHERE from_user=? AND to_user=?",

[target, username],

(e,row)=>{

if(!row) return;



db.serialize(()=>{

db.run(

"INSERT OR IGNORE INTO friends VALUES(?,?,?)",

[u1,u2,Date.now()]

);



db.run(

"DELETE FROM friend_requests WHERE from_user=? AND to_user=?",

[target, username]

);

});

}

);

return;

}



if(type === "FRIEND_REJECT"){

db.run(

"DELETE FROM friend_requests WHERE from_user=? AND to_user=?",

[data.target, username]

);

return;

}



if(type === "FRIEND_DELETE"){

const [u1,u2] = normalizePair(username, data.target);

db.run("DELETE FROM friends WHERE user1=? AND user2=?", [u1,u2]);

return;

}



if(type === "BLOCK_ADD"){

const target = data.target;

if(!target || username === target) return;



db.serialize(()=>{

db.run(

"INSERT OR IGNORE INTO blocks VALUES(?,?,?)",

[username, target, Date.now()]

);



const [u1,u2] = normalizePair(username, target);



db.run("DELETE FROM friends WHERE user1=? AND user2=?", [u1,u2]);



db.run(

"DELETE FROM friend_requests WHERE (from_user=? AND to_user=?) OR (from_user=? AND to_user=?)",

[username, target, target, username]

);

});



return;

}



if(type === "BLOCK_REMOVE"){

db.run(

"DELETE FROM blocks WHERE blocker=? AND blocked=?",

[username, data.target]

);

return;

}



if(type === "FRIENDS_LOAD"){

db.all(

"SELECT * FROM friends WHERE user1=? OR user2=?",

[username, username],

(e,friends)=>{



db.all(

"SELECT * FROM friend_requests WHERE to_user=?",

[username],

(e,requests)=>{



db.all(

"SELECT blocked FROM blocks WHERE blocker=?",

[username],

(e,blocks)=>{



ws.send(JSON.stringify({

type:"FRIENDS_LOAD_RESP",

friends,

requests,

blocks

}));



});

});

});

return;

}



// ================= STATS SAVE =================

if(type === "STATS_SAVE"){

db.get("SELECT secret,last_stats_hash FROM users WHERE username=?", [username], (e,user)=>{

if(!user) return;



if(sign(json, user.secret) !== sig){

flag(username,"BAD_SIGNATURE");

return;

}



const newHash = sha(json);

if(newHash === user.last_stats_hash) return;



db.get("SELECT json FROM player_stats WHERE username=?", [username], (e,row)=>{

const oldS = row ? JSON.parse(row.json) : {};

const newS = JSON.parse(json);



if(isImpossible(oldS,newS)){

flag(username,"IMPOSSIBLE_PROGRESS");

return;

}



db.run(`

INSERT INTO player_stats(username,json)

VALUES(?,?)

ON CONFLICT(username) DO UPDATE SET json=excluded.json

`,[username,json]);



db.run("UPDATE users SET last_stats_hash=? WHERE username=?", [newHash, username]);

fs.writeFileSync(`${BACKUP_DIR}/${username}.json`, json);

});

});

return;

}



// ================= STATS LOAD =================

if(type === "STATS_LOAD"){

db.get("SELECT secret FROM users WHERE username=?", [username], (e,u)=>{

if(!u || u.secret !== secret) return;



db.get("SELECT json FROM player_stats WHERE username=?", [username], (e,row)=>{

ws.send(JSON.stringify({

type:"STATS_LOAD_RESP",

json: row ? row.json : "{}"

}));

});

});

return;

}



// ================= TIER =================

if(type === "TIER_LOAD"){

db.get("SELECT json FROM player_stats WHERE username=?", [username], (e,row)=>{

const stats = row ? JSON.parse(row.json) : {};

const tier = computeTier(stats);

const s = sign("TIER_"+tier, secret);



ws.send(JSON.stringify({ type:"TIER_RESP", tier, sig:s }));

});

}



});



ws.on("close", () => {
if (ws.username) {
broadcastPresence(ws.username, false, "offline");
}
});



});



// ================= START =================

const PORT = process.env.PORT || 3000;

server.listen(PORT, ()=>console.log("Auth server running on", PORT));  

