const WebSocket = require("ws");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

// SQLite setup
const dbFile = path.join(__dirname, "users.db");
const db = new sqlite3.Database(dbFile);

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password_hash TEXT
    )
  `);
});

const wss = new WebSocket.Server({ port: process.env.PORT || 8080 }, () => {
  console.log("WebSocket Auth server running on port", process.env.PORT || 8080);
});

wss.on("connection", (ws) => {
  ws.on("message", (msg) => {
    let data;
    try { data = JSON.parse(msg); } 
    catch { ws.send(JSON.stringify({ type: "ERROR", message: "Invalid JSON" })); return; }

    const { type, username, password_hash } = data;

    if (type === "REGISTER") {
      if (!username || !password_hash) {
        ws.send(JSON.stringify({ type: "REGISTER_RESP", success: false, message: "Missing fields" }));
        return;
      }

      db.run(
        `INSERT INTO users(username, password_hash) VALUES(?, ?)`,
        [username, password_hash],
        function (err) {
          if (err) {
            ws.send(JSON.stringify({ type: "REGISTER_RESP", success: false, message: "Username taken" }));
          } else {
            ws.send(JSON.stringify({ type: "REGISTER_RESP", success: true, message: "Registration OK" }));
          }
        }
      );
    }

    if (type === "LOGIN") {
      if (!username || !password_hash) {
        ws.send(JSON.stringify({ type: "LOGIN_RESP", success: false, message: "Missing fields" }));
        return;
      }

      db.get(`SELECT * FROM users WHERE username=?`, [username], (err, row) => {
        if (err || !row) {
          ws.send(JSON.stringify({ type: "LOGIN_RESP", success: false, message: "Invalid credentials" }));
        } else if (row.password_hash !== password_hash) {
          ws.send(JSON.stringify({ type: "LOGIN_RESP", success: false, message: "Invalid credentials" }));
        } else {
          ws.send(JSON.stringify({ type: "LOGIN_RESP", success: true, message: "Login successful" }));
        }
      });
    }
  });
});
