const http = require("http");
const { WebSocketServer } = require("ws");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const crypto = require("crypto");
const fs = require("fs");

// ================= CONFIG =================
const BACKUP_DIR = "./backups";
if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR);

// ================= HELPERS =================
function makeSecret() {
  return crypto.randomBytes(32).toString("hex");
}

// ================= SQLITE =================
const dbFile = path.join(__dirname, "users.db");
const db = new sqlite3.Database(dbFile);

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      username TEXT PRIMARY KEY,
      password_hash TEXT,
      secret TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS player_stats (
      username TEXT PRIMARY KEY,
      json TEXT
    )
  `);
});

// ================= HTTP (Railway requires this) =================
const server = http.createServer((req, res) => {
  res.writeHead(200);
  res.end("WebSocket Auth Server Online");
});

// ================= WEBSOCKET =================
const wss = new WebSocketServer({ server });

wss.on("connection", (ws) => {
  console.log("Client connected");

  ws.on("message", (msg) => {
    let data;
    try {
      data = JSON.parse(msg.toString());
    } catch {
      ws.send(JSON.stringify({ type: "ERROR", message: "Invalid JSON" }));
      return;
    }

    const { type, username, password_hash, secret, json } = data;

    // ================= REGISTER =================
    if (type === "REGISTER") {
      const newSecret = makeSecret();

      db.run(
        `INSERT INTO users(username, password_hash, secret) VALUES(?,?,?)`,
        [username, password_hash, newSecret],
        (err) => {
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
              secret: newSecret
            }));
          }
        }
      );
    }

    // ================= LOGIN =================
    if (type === "LOGIN") {
      db.get(
        `SELECT password_hash, secret FROM users WHERE username=?`,
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
              secret: row.secret
            }));
          }
        }
      );
    }

    // ================= STATS LOAD =================
    if (type === "STATS_LOAD") {
      db.get(
        `SELECT secret FROM users WHERE username=?`,
        [username],
        (err, row) => {
          if (!row || row.secret !== secret) return;

          db.get(
            `SELECT json FROM player_stats WHERE username=?`,
            [username],
            (err, statsRow) => {
              ws.send(JSON.stringify({
                type: "STATS_LOAD_RESP",
                json: statsRow ? statsRow.json : "{}"
              }));
            }
          );
        }
      );
    }

    // ================= STATS SAVE =================
    if (type === "STATS_SAVE") {
      db.get(
        `SELECT secret FROM users WHERE username=?`,
        [username],
        (err, row) => {
          if (!row || row.secret !== secret) {
            console.log("Tamper attempt:", username);
            return;
          }

          db.run(
            `INSERT INTO player_stats(username,json)
             VALUES(?,?)
             ON CONFLICT(username) DO UPDATE SET json=excluded.json`,
            [username, json]
          );

          fs.writeFileSync(`${BACKUP_DIR}/${username}.json`, json);
        }
      );
    }
  });
});

// ================= START =================
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log("Auth server running on", PORT);
});