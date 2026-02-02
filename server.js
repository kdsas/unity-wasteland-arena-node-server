const http = require("http");
const { WebSocketServer } = require("ws");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const crypto = require("crypto");

const fs = require("fs");
const BACKUP_DIR = "./backups";
if(!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR);

function makeSecret() {
  return crypto.randomBytes(32).toString("hex");
}

function sign(data, secret) {
  return crypto.createHmac("sha256", secret).update(data).digest("base64");
}

// ================= SQLITE =================
const dbFile = path.join(__dirname, "users.db");
const db = new sqlite3.Database(dbFile);
fs.writeFileSync(`${BACKUP_DIR}/${username}.json`, json);

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password_hash TEXT,
      secret TEXT
    )
  `);
});

 // Auto-migrate old databases
  db.run(`ALTER TABLE users ADD COLUMN secret TEXT`, (err) => {
    if (err) {
      if (!err.message.includes("duplicate column")) {
        console.error("Migration error:", err.message);
      }
    } else {
      console.log("Migrated: secret column added");
    }
  });
});

db.run(`
CREATE TABLE IF NOT EXISTS player_stats (
  username TEXT PRIMARY KEY,
  json TEXT
)
`);


// ================= HTTP SERVER (REQUIRED BY RAILWAY) =================
const server = http.createServer((req, res) => {
  res.writeHead(200);
  res.end("Auth server online");
});

// ================= WEBSOCKET =================
const wss = new WebSocketServer({ server });

wss.on("connection", (ws) => {
  console.log("Client connected");

  ws.on("message", (msg) => {
    console.log("Received:", msg.toString());

    let data;
    try {
      data = JSON.parse(msg);
    } catch {
      ws.send(JSON.stringify({ type: "ERROR", message: "Invalid JSON" }));
      return;
    }

    const { type, username, password_hash } = data;
    if (data.type === "STATS_LOAD") {
  db.get("SELECT json FROM player_stats WHERE username=?", [data.username], (err,row)=>{
    ws.send(JSON.stringify({
      type:"STATS_LOAD_RESP",
      json: row ? row.json : "{}"
    }));
  });
}

if (data.type === "STATS_SAVE") {
  db.run(
    `INSERT INTO player_stats(username,json)
     VALUES(?,?)
     ON CONFLICT(username) DO UPDATE SET json=excluded.json`,
    [data.username, data.json]
  );
}


    // ================= REGISTER =================
    if (type === "REGISTER") {
      if (!username || !password_hash) {
        ws.send(JSON.stringify({
          type: "REGISTER_RESP",
          success: false,
          message: "Missing fields"
        }));
        return;
      }
     const secret = makeSecret();
      db.run(
        `INSERT INTO users(username, password_hash, secret) VALUES(?, ?, ?)`,
        [username, password_hash, secret],
        function (err) {
          if (err) {
            ws.send(JSON.stringify({
              type: "REGISTER_RESP",
              success: false,
              message: "Username taken"
            }));
          } else {
            ws.send(JSON.stringify({
              type: "REGISTER_RESP",
              success: true,
              message: "Registration OK"
            }));
	   ws.send(JSON.stringify({
              type: "REGISTER_RESP",
              success: true,
              secret
              }));

          }
        }
      );
    }

    // ================= LOGIN =================
    if (type === "LOGIN") {
      if (!username || !password_hash) {
        ws.send(JSON.stringify({
          type: "LOGIN_RESP",
          success: false,
          message: "Missing fields"
        }));
        return;
      }
    db.get("SELECT secret FROM users WHERE username=?", [username], (err,row)=>{
         if(!row) return;

         const goodSig = sign(json, row.secret);

         if(sig !== goodSig){
         console.log("TAMPER DETECTED:", username);
         return;
        }

       // save json to stats table
      });
    db.get("SELECT json FROM stats WHERE username=?", [username], (err,row)=>{
  if(!row){
    const path = `${BACKUP_DIR}/${username}.json`;
    if(fs.existsSync(path)){
      const json = fs.readFileSync(path,"utf8");
      db.run("INSERT INTO stats(username,json) VALUES(?,?)",[username,json]);
    }
  }
});

      db.get(
        `SELECT * FROM users WHERE username=?`,
        [username],
        (err, row) => {
          if (!row || row.password_hash !== password_hash) {
            ws.send(JSON.stringify({
              type: "LOGIN_RESP",
              success: false,
              message: "Invalid credentials"
            }));
          } else {
            ws.send(JSON.stringify({
              type: "LOGIN_RESP",
              success: true,
              message: "Login successful"
            }));
          }
        }
      );
    }
  });
});

// ================= RAILWAY PORT =================
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log("Auth server running on", PORT);
});
