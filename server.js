const http = require("http");
const { WebSocketServer } = require("ws");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

// ================= SQLITE =================
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

      db.run(
        `INSERT INTO users(username, password_hash) VALUES(?, ?)`,
        [username, password_hash],
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
