const http = require("http");
const { WebSocketServer } = require("ws");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

// Random permanent community-admin slots.
// Change this one number if you want more/fewer admins.
const RANDOM_ADMIN_COUNT = 3;

// ============================================================
// CONFIGURATION
// ============================================================

// Railway Volume should be mounted at:
//
// /data
//
// Optional environment override:
//
// DB_DIR=/data
//
// Persistent SQLite database:
//
// /data/users.db
//
// Persistent backups:
//
// /data/backups/

const DB_DIR = process.env.DB_DIR || "/data";

// ============================================================
// PERSISTENT STORAGE DIRECTORY
// ============================================================

// Make sure the Railway Volume directory exists.

if (!fs.existsSync(DB_DIR)) {
    fs.mkdirSync(
        DB_DIR,
        { recursive: true }
    );
}

// ============================================================
// BACKUP DIRECTORY
// ============================================================

const BACKUP_DIR = path.join(DB_DIR, "backups");

if (!fs.existsSync(BACKUP_DIR)) {
    fs.mkdirSync(
        BACKUP_DIR,
        { recursive: true }
    );
}

// ============================================================
// STORAGE PATHS
// ============================================================

const DB_PATH = path.join(DB_DIR, "users.db");

console.log("==========================================");
console.log("Persistent storage configuration");
console.log("DB_DIR:", DB_DIR);
console.log("DB_PATH:", DB_PATH);
console.log("BACKUP_DIR:", BACKUP_DIR);
console.log("==========================================");

// ============================================================
// HELPERS
// ============================================================

function makeSecret() {
    return crypto
        .randomBytes(32)
        .toString("hex");
}

function sign(data, secret) {
    return crypto
        .createHmac("sha256", secret)
        .update(data)
        .digest("base64");
}

function sha(s) {
    return crypto
        .createHash("sha256")
        .update(s)
        .digest("hex");
}

function normalizePair(a, b) {
    return a < b
        ? [a, b]
        : [b, a];
}

// ============================================================
// RANDOM PERMANENT ADMINS
// ============================================================

function ensureRandomAdmins() {
    db.get(
        `SELECT COUNT(*) AS count FROM moderators WHERE active=1`,
        [],
        (e, row) => {
            if (e) {
                console.error("❌ Admin count check failed:", e.message);
                return;
            }

            const current = row ? row.count : 0;
            const needed = RANDOM_ADMIN_COUNT - current;

            if (needed <= 0) return;

            db.all(
                `
                SELECT username
                FROM users
                WHERE username NOT IN (SELECT username FROM moderators)
                ORDER BY RANDOM()
                LIMIT ?
                `,
                [needed],
                (err, players) => {
                    if (err) {
                        console.error("❌ Random admin selection failed:", err.message);
                        return;
                    }

                    (players || []).forEach(player => {
                        db.run(
                            `INSERT OR IGNORE INTO moderators(username,selected_at,active) VALUES(?,?,1)`,
                            [player.username, Date.now()],
                            insertErr => {
                                if (!insertErr) {
                                    console.log("👑 Random admin selected:", player.username);
                                }
                            }
                        );
                    });
                }
            );
        }
    );
}

function getAdmin(username, cb) {
    db.get(
        `SELECT 1 FROM moderators WHERE username=? AND active=1`,
        [username],
        (e, row) => cb(!e && !!row)
    );
}
// ============================================================
// PRESENCE
// ============================================================

function broadcastPresence(username, online, state) {
    wss.clients.forEach(c => {
        if (c.readyState === 1) {
            c.send(JSON.stringify({
                type: "PRESENCE_UPDATE",
                username,
                online,
                state
            }));
        }
    });
}

// ============================================================
// SQLITE
// ============================================================

const db = new sqlite3.Database(
    DB_PATH,
    (err) => {
        if (err) {
            console.error("❌ SQLite database failed to open:");
            console.error(err);
            process.exit(1);
        }

        console.log("✅ SQLite database opened:");
        console.log(DB_PATH);
    }
);

// ============================================================
// SQLITE PERFORMANCE / SAFETY
// ============================================================

db.serialize(() => {
    // WAL allows SQLite to handle reads
    // while writes are occurring.
    db.run(
        "PRAGMA journal_mode = WAL",
        err => {
            if (err) {
                console.error("❌ SQLite WAL mode error:", err.message);
            } else {
                console.log("✅ SQLite WAL mode enabled");
            }
        }
    );

    // Good balance between durability
    // and performance for this server.
    db.run(
        "PRAGMA synchronous = NORMAL",
        err => {
            if (err) {
                console.error("❌ SQLite synchronous setting error:", err.message);
            }
        }
    );

    // Prevent immediate SQLITE_BUSY failures
    // when multiple operations briefly overlap.
    db.run(
        "PRAGMA busy_timeout = 5000",
        err => {
            if (err) {
                console.error("❌ SQLite busy timeout error:", err.message);
            }
        }
    );
});
// ============================================================
// DATABASE TABLES
// ============================================================

db.serialize(() => {

    // ================= USERS =================

    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT,
            secret TEXT,
            cheat_flags INTEGER DEFAULT 0,
            last_stats_hash TEXT,
            device TEXT
        )
    `);

    // ================= PLAYER STATS =================

    db.run(`
        CREATE TABLE IF NOT EXISTS player_stats (
            username TEXT PRIMARY KEY,
            json TEXT
        )
    `);

    // ================= HWID BANS =================

    db.run(`
        CREATE TABLE IF NOT EXISTS hwid_bans (
            hwid TEXT PRIMARY KEY,
            reason TEXT,
            created_at INTEGER
        )
    `);

    // ================= FRIENDS =================

    db.run(`
        CREATE TABLE IF NOT EXISTS friends (
            user1 TEXT,
            user2 TEXT,
            created_at INTEGER,
            UNIQUE(user1,user2)
        )
    `);

    // ================= FRIEND REQUESTS =================

    db.run(`
        CREATE TABLE IF NOT EXISTS friend_requests (
            from_user TEXT,
            to_user TEXT,
            created_at INTEGER,
            UNIQUE(from_user,to_user)
        )
    `);

    // ================= BLOCKS =================

    db.run(`
        CREATE TABLE IF NOT EXISTS blocks (
            blocker TEXT,
            blocked TEXT,
            created_at INTEGER,
            UNIQUE(blocker,blocked)
        )
    `);

    // ================= RANDOM ADMINS =================

    db.run(`
        CREATE TABLE IF NOT EXISTS moderators (
            username TEXT PRIMARY KEY,
            selected_at INTEGER,
            active INTEGER DEFAULT 1
        )
    `);

    // ================= ACCOUNT BANS =================

    db.run(`
        CREATE TABLE IF NOT EXISTS account_bans (
            username TEXT PRIMARY KEY,
            reason TEXT,
            banned_by TEXT,
            created_at INTEGER
        )
    `);

    // ================= TRUSTED DEVICES =================

    db.run(`
        CREATE TABLE IF NOT EXISTS trusted_devices (
            username TEXT NOT NULL,
            device_id TEXT NOT NULL,
            public_key TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY(username, device_id)
        )
    `);

    // ================= PLAYER REPORTS =================

    db.run(`
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter TEXT,
            target TEXT,
            reason TEXT,
            created_at INTEGER,
            status TEXT DEFAULT 'open'
        )
    `, () => {
        ensureRandomAdmins();
    });

});
// ============================================================
// BLOCK CHECK
// ============================================================

function isBlocked(a, b, cb) {
    db.get(
        `
        SELECT 1
        FROM blocks
        WHERE
            (blocker=? AND blocked=?)
            OR
            (blocker=? AND blocked=?)
        `,
        [a, b, b, a],
        (e, row) => {
            cb(!!row);
        }
    );
}

// ============================================================
// HWID
// ============================================================

function banHWID(hwid, reason) {
    if (!hwid) {
        return;
    }

    db.run(
        `
        INSERT OR IGNORE INTO hwid_bans
        VALUES(?,?,?)
        `,
        [hwid, reason, Date.now()],
        err => {
            if (err) {
                console.error("❌ Failed to ban HWID:", err.message);
            }
        }
    );
}

function isHWIDBanned(hwid, cb) {
    if (!hwid) {
        cb(null);
        return;
    }

    db.get(
        `
        SELECT reason
        FROM hwid_bans
        WHERE hwid=?
        `,
        [hwid],
        (e, row) => {
            cb(row ? row.reason : null);
        }
    );
}
// ============================================================
// CHEAT DETECTION
// ============================================================

function isImpossible(oldS, newS) {
    if (!oldS || !oldS.kills) {
        return false;
    }

    if (
        (newS.kills || 0) -
        (oldS.kills || 0) > 50
    ) {
        return true;
    }

    if (
        (newS.bossKills || 0) -
        (oldS.bossKills || 0) > 3
    ) {
        return true;
    }

    if (
        (newS.xp || 0) -
        (oldS.xp || 0) > 10000
    ) {
        return true;
    }

    if (
        (newS.timeSurvived || 0) -
        (oldS.timeSurvived || 0) > 3600
    ) {
        return true;
    }

    return false;
}

function flag(username, reason) {
    console.warn("[SECURITY]", username, reason);

    // A signature mismatch is not proof of cheating.
    // Reject the invalid request, but do not penalize the account
    // or hardware-ban the device.
    if (reason === "BAD_SIGNATURE") {
        console.warn(
            "[AUTH] Signature rejected; no cheat flag or HWID ban applied."
        );
        return;
    }

    // Only confirmed impossible-progress detections affect cheat flags
    // or trigger the existing HWID-ban rule.
    if (reason !== "IMPOSSIBLE_PROGRESS") {
        console.warn(
            "[SECURITY] No automatic penalty for:", reason
        );
        return;
    }

    db.get(
        "SELECT device FROM users WHERE username = ?",
        [username],
        (err, row) => {
            if (err) {
                console.error(
                    "[SECURITY] Could not read account device:",
                    err.message
                );
                return;
            }

            if (row && row.device) {
                banHWID(row.device, "Cheating");
            }
        }
    );

    db.run(
        `UPDATE users
         SET cheat_flags = COALESCE(cheat_flags, 0) + 1
         WHERE username = ?`,
        [username],
        err => {
            if (err) {
                console.error(
                    "[SECURITY] Could not update cheat flags:",
                    err.message
                );
            }
        }
    );
}

// ============================================================
// TIER
// ============================================================

function computeTier(stats) {
    if ((stats.bossKills || 0) >= 25) {
        return 7;
    }

    if ((stats.bossKills || 0) >= 18) {
        return 6;
    }

    if ((stats.bossKills || 0) >= 12) {
        return 5;
    }

    if ((stats.bossKills || 0) >= 8) {
        return 4;
    }

    if ((stats.bossKills || 0) >= 5) {
        return 3;
    }

    if ((stats.bossKills || 0) >= 3) {
        return 2;
    }

    return 1;
}
// ============================================================
// TRUSTED DEVICE REGISTRATION
// ============================================================

function base64Url(value) {
    return Buffer.from(value, "base64")
        .toString("base64")
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
}

function rsaXmlToPublicKey(xml) {
    const readTag = name => {
        const match = String(xml || "").match(
            new RegExp(`<${name}>([^<]+)</${name}>`)
        );

        return match ? match[1] : null;
    };

    const modulus = readTag("Modulus");
    const exponent = readTag("Exponent");

    if (!modulus || !exponent) {
        throw new Error("Invalid RSA XML public key.");
    }

    return crypto.createPublicKey({
        key: {
            kty: "RSA",
            n: base64Url(modulus),
            e: base64Url(exponent)
        },
        format: "jwk"
    });
}

function handleDeviceRegistration(ws, data) {
    const username = String(data.username || "").trim();
    const secret = String(data.secret || "");
    const deviceId = String(data.deviceId || "").trim();
    const publicKeyXml = String(data.publicKey || "");
    const timestamp = Number(data.timestamp);
    const signature = String(data.signature || "");

    const respond = (success, message, deviceToken = null) => {
        if (ws.readyState === 1) {
            ws.send(JSON.stringify({
                type: "DEVICE_REGISTER_RESP",
                success,
                message,
                deviceToken
            }));
        }
    };

    if (
        !username ||
        !secret ||
        !deviceId ||
        !publicKeyXml ||
        !Number.isFinite(timestamp) ||
        !signature
    ) {
        respond(false, "Device registration request is incomplete.");
        return;
    }

    // Reject stale or future-dated signed requests (5-minute window).
    const nowSeconds = Math.floor(Date.now() / 1000);

    if (Math.abs(nowSeconds - timestamp) > 300) {
        respond(
            false,
            "Device registration request expired. Please try again."
        );
        return;
    }

    db.get(
        "SELECT secret FROM users WHERE username = ?",
        [username],
        (lookupErr, user) => {
            if (lookupErr || !user || user.secret !== secret) {
                respond(
                    false,
                    "Authentication failed. Please log in again."
                );
                return;
            }

            try {
                const signingData = `${username}|${deviceId}|${timestamp}`;
                const publicKey = rsaXmlToPublicKey(publicKeyXml);
                const signatureBytes = Buffer.from(signature, "base64");

                const valid = crypto.verify(
                    "sha256",
                    Buffer.from(signingData, "utf8"),
                    publicKey,
                    signatureBytes
                );

                if (!valid) {
                    console.warn(
                        "[DEVICE REGISTER] Invalid device proof for account:",
                        username
                    );

                    respond(
                        false,
                        "Device proof could not be verified. Please retry."
                    );
                    return;
                }

                const deviceToken = crypto.randomBytes(32).toString("hex");
                const tokenHash = sha(deviceToken);

                db.run(
                    `INSERT INTO trusted_devices
                        (username, device_id, public_key, token_hash, created_at)
                     VALUES (?, ?, ?, ?, ?)
                     ON CONFLICT(username, device_id) DO UPDATE SET
                        public_key = excluded.public_key,
                        token_hash = excluded.token_hash,
                        created_at = excluded.created_at`,
                    [
                        username,
                        deviceId,
                        publicKeyXml,
                        tokenHash,
                        Date.now()
                    ],
                    saveErr => {
                        if (saveErr) {
                            console.error(
                                "[DEVICE REGISTER] Database write failed:",
                                saveErr.message
                            );

                            respond(
                                false,
                                "Could not save trusted device. Please try again."
                            );
                            return;
                        }

                        console.log(
                            "[DEVICE REGISTER] Trusted device saved for",
                            username
                        );

                        respond(
                            true,
                            "Device trusted successfully.",
                            deviceToken
                        );
                    }
                );
            } catch (err) {
                console.error(
                    "[DEVICE REGISTER] Verification error:",
                    err.message
                );

                respond(
                    false,
                    "Device registration could not be verified."
                );
            }
        }
    );
}
// ============================================================
// HTTP SERVER
// ============================================================

const ADMIN_RESET_TOKEN = process.env.ADMIN_RESET_TOKEN || "";

function runDatabaseStatement(sql) {
    return new Promise((resolve, reject) => {
        db.run(sql, err => err ? reject(err) : resolve());
    });
}

async function resetDatabaseAndBackups() {
    const tablesToClear = [
        "player_stats",
        "friends",
        "friend_requests",
        "blocks",
        "reports",
        "account_bans",
        "hwid_bans",
        "trusted_devices",
        "moderators",
        "users"
    ];

    await runDatabaseStatement("BEGIN IMMEDIATE TRANSACTION");

    try {
        for (const table of tablesToClear) {
            // Table names are a fixed server-owned allowlist above.
            await runDatabaseStatement(`DELETE FROM ${table}`);
        }

        await runDatabaseStatement(
            "DELETE FROM sqlite_sequence WHERE name='reports'"
        );

        await runDatabaseStatement("COMMIT");
    } catch (err) {
        try {
            await runDatabaseStatement("ROLLBACK");
        } catch {}

        throw err;
    }

    // Remove saved player-stat JSON backups from the persistent volume.
    for (const entry of fs.readdirSync(BACKUP_DIR, { withFileTypes: true })) {
        if (entry.isFile()) {
            fs.unlinkSync(path.join(BACKUP_DIR, entry.name));
        }
    }

    // Invalidate all existing authenticated sessions after a full wipe.
    if (typeof wss !== "undefined") {
        wss.clients.forEach(client => {
            try {
                client.close(4001, "Server data reset; please reconnect");
            } catch {}
        });
    }
}

function safeTokenEquals(candidate, expected) {
    if (typeof candidate !== "string" || !expected) return false;

    const a = Buffer.from(candidate, "utf8");
    const b = Buffer.from(expected, "utf8");

    return a.length === b.length &&
        crypto.timingSafeEqual(a, b);
}

const server = http.createServer((req, res) => {
    const requestUrl = new URL(
        req.url,
        `http://${req.headers.host || "localhost"}`
    );

    if (requestUrl.pathname === "/health" && req.method === "GET") {
        res.writeHead(200, {
            "Content-Type": "text/plain; charset=utf-8"
        });

        res.end("OK");
        return;
    }

    if (requestUrl.pathname === "/admin/reset" && req.method === "GET") {
        if (!ADMIN_RESET_TOKEN) {
            res.writeHead(503, {
                "Content-Type": "text/plain; charset=utf-8"
            });

            res.end(
                "Database reset is disabled. Set ADMIN_RESET_TOKEN in the server environment to enable it."
            );

            return;
        }

        res.writeHead(200, {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store"
        });

        res.end(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Wasteland Arena — Database Reset</title>
<style>body{font:16px system-ui,sans-serif;max-width:620px;margin:50px auto;padding:0 20px;background:#171717;color:#eee}main{border:1px solid #633;padding:24px;border-radius:12px;background:#222}label{display:block;margin:18px 0 6px}input{box-sizing:border-box;width:100%;padding:12px;background:#111;color:#fff;border:1px solid #777;border-radius:6px}button{margin-top:20px;padding:12px 18px;background:#a21d2b;color:#fff;border:0;border-radius:6px;font-weight:700;cursor:pointer}p{line-height:1.5}.warning{color:#ff9b9b;font-weight:700}</style></head>
<body><main><h1>Reset game database</h1>
<p class="warning">This permanently deletes all accounts, player stats, friendships, reports, moderator assignments, account bans, hardware bans, trusted devices, and JSON stat backups.</p>
<p>This does not delete the database schema. Players will need to register again. This action cannot be undone.</p>
<form method="post" action="/admin/reset" onsubmit="return confirm('FINAL WARNING: permanently erase all game data?');">
<label for="token">Admin reset token</label><input id="token" name="token" type="password" autocomplete="current-password" required>
<label for="confirmation">Type RESET ALL DATA to confirm</label><input id="confirmation" name="confirmation" required autocomplete="off">
<button type="submit">DELETE ALL GAME DATA</button></form></main></body></html>`);

        return;
    }

    if (requestUrl.pathname === "/admin/reset" && req.method === "POST") {
        if (!ADMIN_RESET_TOKEN) {
            res.writeHead(503, {
                "Content-Type": "text/plain; charset=utf-8"
            });

            res.end("Database reset is disabled.");
            return;
        }

        let body = "";

        req.on("data", chunk => {
            body += chunk.toString("utf8");

            if (body.length > 8192) req.destroy();
        });

        req.on("end", async () => {
            const form = new URLSearchParams(body);
            const token = form.get("token") || "";
            const confirmation = form.get("confirmation") || "";

            if (!safeTokenEquals(token, ADMIN_RESET_TOKEN)) {
                res.writeHead(403, {
                    "Content-Type": "text/plain; charset=utf-8"
                });

                res.end("Forbidden: invalid admin reset token.");
                return;
            }

            if (confirmation !== "RESET ALL DATA") {
                res.writeHead(400, {
                    "Content-Type": "text/plain; charset=utf-8"
                });

                res.end("Reset cancelled: confirmation phrase did not match.");
                return;
            }

            try {
                await resetDatabaseAndBackups();

                console.warn(
                    "[ADMIN RESET] All game data and stat backups were deleted by explicit admin action."
                );

                res.writeHead(200, {
                    "Content-Type": "text/html; charset=utf-8",
                    "Cache-Control": "no-store"
                });

                res.end("<!doctype html><html><head><meta charset='utf-8'><title>Reset complete</title></head><body style='font:16px system-ui;max-width:620px;margin:50px auto;padding:0 20px'><h1>Database reset complete</h1><p>All player accounts, game data, hardware bans, account bans, moderator assignments, trusted devices, and JSON stat backups were cleared. The database tables remain ready for new registrations.</p><p>You can close this page.</p></body></html>");
            } catch (err) {
                console.error("[ADMIN RESET] Failed:", err);

                res.writeHead(500, {
                    "Content-Type": "text/plain; charset=utf-8"
                });

                res.end(
                    "Database reset failed. Check the server logs; the transaction was rolled back if the database deletion failed."
                );
            }
        });

        return;
    }

    res.writeHead(200, {
        "Content-Type": "text/plain; charset=utf-8"
    });

    res.end("Auth server online");
});
// ============================================================
// WEBSOCKET SERVER
// ============================================================

const wss = new WebSocketServer({
    server
});

wss.on(
    "connection",
    (ws) => {
        console.log("🔌 WebSocket client connected");

        // ====================================================
        // MESSAGE
        // ====================================================

        ws.on("message", (msg) => {
            let data;

            try {
                data = JSON.parse(msg.toString());
            } catch {
                console.log("⚠️ Invalid JSON received");
                return;
            }

            const {
                type,
                username,
                password_hash,
                json,
                sig,
                secret,
                device
            } = data;

            if (!type || !username) {
                return;
            }

            // DEVICE_REGISTER uses a per-device RSA proof and the account secret,
            // not the generic HMAC `sig` field used by other message types.
            if (type === "DEVICE_REGISTER") {
                handleDeviceRegistration(ws, data);
                return;
            }

            // ====================================================
            // SECURITY
            // ====================================================

            // REGISTER and LOGIN are the only
            // messages that do not require
            // an existing secret.

            if (type !== "REGISTER" && type !== "LOGIN") {
                if (!secret) {
                    return;
                }

                if (sign(username, secret) !== sig) {
                    flag(username, "BAD_SIGNATURE");
                    return;
                }
            }

            // ====================================================
            // SERVER-AUTHORITATIVE ADMIN STATUS
            // ====================================================

            getAdmin(username, (admin) => {
                ws.username = username;
                ws.isAdmin = admin;

                if (ws.adminStatus !== admin) {
                    ws.adminStatus = admin;

                    ws.send(JSON.stringify({
                        type: "ADMIN_STATUS",
                        admin: admin
                    }));
                }
            });

                        // ====================================================
            // PRESENCE
            // ====================================================

            if (type === "PRESENCE_SET") {
                ws.presence = data.state || "online";
                ws.username = username;

                broadcastPresence(
                    username,
                    true,
                    ws.presence
                );

                return;
            }

            // ====================================================
            // CHAT
            // ====================================================

            if (type === "CHAT") {
                const {
                    message,
                    channel,
                    target,
                    msgId
                } = data;

                if (!message || message.length > 200) {
                    return;
                }

                // Server-side spam throttle.
                if (!ws.lastChat) {
                    ws.lastChat = 0;
                }

                if (Date.now() - ws.lastChat < 200) {
                    return;
                }

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

                // IMPORTANT:
                // Chat is intentionally broadcast to every connected client.
                // SimpleChatUI performs the final whisper visibility filtering.
                // DO NOT change this to target-only routing.

                wss.clients.forEach(client => {
                    if (client.readyState === 1) {
                        client.send(payload);
                    }
                });

                return;
            }

            // ====================================================
            // REGISTER
            // ====================================================

            if (type === "REGISTER") {
                const s = makeSecret();

                db.run(
                    `
                    INSERT INTO users(
                        username,
                        password_hash,
                        secret,
                        device
                    )
                    VALUES(?,?,?,?)
                    `,
                    [
                        username,
                        password_hash,
                        s,
                        device
                    ],
                    err => {
                        if (err) {
                            const usernameExists =
                                err.code === "SQLITE_CONSTRAINT" &&
                                /users\.username/.test(err.message);

                            const message = usernameExists
                                ? "Username already exists. Please log in instead."
                                : "Registration failed. Please try again.";

                            console.error(
                                "[REGISTER]",
                                usernameExists
                                    ? "Username already exists:"
                                    : "Registration failed:",
                                username,
                                err.message
                            );

                            ws.send(JSON.stringify({
                                type: "REGISTER_RESP",
                                success: false,
                                message
                            }));

                            return;
                        }

                        console.log("Registered user:", username);

                        ensureRandomAdmins();

                        ws.send(JSON.stringify({
                            type: "REGISTER_RESP",
                            success: true,
                            secret: s,
                            message: "Registration successful."
                        }));
                    }
                );

                return;
            }

                        // ====================================================
            // LOGIN
            // ====================================================

            if (type === "LOGIN") {
                isHWIDBanned(device, (reason) => {
                    if (reason) {
                        ws.send(JSON.stringify({
                            type: "LOGIN_RESP",
                            success: false,
                            message: "HWID BANNED: " + reason
                        }));

                        return;
                    }

                    db.get(
                        `
                        SELECT
                            password_hash,
                            secret,
                            cheat_flags,
                            device
                        FROM users
                        WHERE username=?
                        `,
                        [username],
                        (e, row) => {
                            if (!row || row.password_hash !== password_hash) {
                                ws.send(JSON.stringify({
                                    type: "LOGIN_RESP",
                                    success: false
                                }));

                                return;
                            }

                            db.get(
                                `SELECT reason FROM account_bans WHERE username=?`,
                                [username],
                                (banErr, banRow) => {
                                    if (banRow) {
                                        ws.send(JSON.stringify({
                                            type: "LOGIN_RESP",
                                            success: false,
                                            message: "Account banned: " +
                                                (banRow.reason || "Moderator ban")
                                        }));

                                        return;
                                    }

                                    if (row.cheat_flags >= 3) {
                                        ws.send(JSON.stringify({
                                            type: "LOGIN_RESP",
                                            success: false,
                                            message: "Account banned"
                                        }));

                                        return;
                                    }

                                    // Bind the account to its first device only when
                                    // no device has been recorded. A different device
                                    // is not evidence of cheating and must not be banned.
                                    if (!row.device && device) {
                                        db.run(
                                            `UPDATE users SET device=? WHERE username=?`,
                                            [device, username],
                                            bindErr => {
                                                if (bindErr) {
                                                    console.error(
                                                        "[LOGIN] Could not save initial device:",
                                                        bindErr.message
                                                    );
                                                }
                                            }
                                        );
                                    }

                                    getAdmin(username, (admin) => {
                                        ws.username = username;
                                        ws.isAdmin = admin;
                                        ws.adminStatus = admin;

                                        ws.send(JSON.stringify({
                                            type: "LOGIN_RESP",
                                            success: true,
                                            secret: row.secret,
                                            flags: row.cheat_flags,
                                            admin: admin
                                        }));

                                        ws.send(JSON.stringify({
                                            type: "ADMIN_STATUS",
                                            admin: admin
                                        }));
                                    });
                                }
                            );
                        }
                    );
                });

                return;
            }

            // ====================================================
            // PLAYER REPORT
            // ====================================================

            if (type === "REPORT_PLAYER") {
                const target = String(data.target || "").trim();
                const reason = String(data.reason || "")
                    .trim()
                    .slice(0, 500);

                if (!target || target === username || !reason) {
                    ws.send(JSON.stringify({
                        type: "REPORT_PLAYER_RESP",
                        success: false,
                        message: "Invalid report."
                    }));

                    return;
                }

                // Small server-side report throttle.
                const now = Date.now();

                if (!ws.reportWindow || now - ws.reportWindow >= 60000) {
                    ws.reportWindow = now;
                    ws.reportCount = 0;
                }

                if ((ws.reportCount || 0) >= 5) {
                    ws.send(JSON.stringify({
                        type: "REPORT_PLAYER_RESP",
                        success: false,
                        message: "Too many reports. Try again later."
                    }));

                    return;
                }

                db.get(
                    `SELECT username FROM users WHERE username=?`,
                    [target],
                    (e, targetRow) => {
                        if (!targetRow) {
                            ws.send(JSON.stringify({
                                type: "REPORT_PLAYER_RESP",
                                success: false,
                                message: "Player does not exist."
                            }));

                            return;
                        }

                        ws.reportCount = (ws.reportCount || 0) + 1;

                        db.run(
                            `INSERT INTO reports(reporter,target,reason,created_at,status)
                             VALUES(?,?,?,?,?)`,
                            [username, target, reason, Date.now(), "open"],
                            err => {
                                ws.send(JSON.stringify({
                                    type: "REPORT_PLAYER_RESP",
                                    success: !err,
                                    message: err
                                        ? "Report failed."
                                        : "Report submitted."
                                }));
                            }
                        );
                    }
                );

                return;
            }

            // ====================================================
            // ADMIN REPORTS LOAD
            // ====================================================

            if (type === "REPORTS_LOAD") {
                getAdmin(username, (admin) => {
                    if (!admin) {
                        ws.send(JSON.stringify({
                            type: "REPORTS_LOAD_RESP",
                            success: false,
                            reports: []
                        }));

                        return;
                    }

                    db.all(
                        `SELECT id, reporter, target, reason, created_at, status
                         FROM reports
                         WHERE status='open'
                         ORDER BY created_at DESC
                         LIMIT 100`,
                        [],
                        (e, reports) => {
                            ws.send(JSON.stringify({
                                type: "REPORTS_LOAD_RESP",
                                success: !e,
                                reports: reports || []
                            }));
                        }
                    );
                });

                return;
            }
            // ====================================================
            // ADMIN ACCOUNT BAN
            // ====================================================

            if (type === "ACCOUNT_BAN") {
                getAdmin(username, (admin) => {
                    if (!admin) {
                        ws.send(JSON.stringify({
                            type: "ACCOUNT_BAN_RESP",
                            success: false,
                            message: "Not authorized."
                        }));

                        return;
                    }

                    const target = String(data.target || "").trim();
                    const reason = String(
                        data.reason || "Moderator ban"
                    ).trim().slice(0, 300) || "Moderator ban";

                    if (!target || target === username) {
                        ws.send(JSON.stringify({
                            type: "ACCOUNT_BAN_RESP",
                            success: false,
                            message: "You cannot ban yourself."
                        }));

                        return;
                    }

                    getAdmin(target, (targetIsAdmin) => {
                        if (targetIsAdmin) {
                            ws.send(JSON.stringify({
                                type: "ACCOUNT_BAN_RESP",
                                success: false,
                                message: "Admins cannot ban another admin."
                            }));

                            return;
                        }

                        db.get(
                            `SELECT username FROM users WHERE username=?`,
                            [target],
                            (e, row) => {
                                if (!row) {
                                    ws.send(JSON.stringify({
                                        type: "ACCOUNT_BAN_RESP",
                                        success: false,
                                        message: "Player does not exist."
                                    }));

                                    return;
                                }

                                db.run(
                                    `INSERT INTO account_bans(username,reason,banned_by,created_at)
                                     VALUES(?,?,?,?)
                                     ON CONFLICT(username) DO UPDATE SET
                                         reason=excluded.reason,
                                         banned_by=excluded.banned_by,
                                         created_at=excluded.created_at`,
                                    [target, reason, username, Date.now()],
                                    err => {
                                        if (err) {
                                            ws.send(JSON.stringify({
                                                type: "ACCOUNT_BAN_RESP",
                                                success: false,
                                                message: "Ban failed."
                                            }));

                                            return;
                                        }

                                        ws.send(JSON.stringify({
                                            type: "ACCOUNT_BAN_RESP",
                                            success: true,
                                            target: target,
                                            message: "Account banned."
                                        }));

                                        // Immediately remove the banned account if online.
                                        wss.clients.forEach(client => {
                                            if (client.username === target) {
                                                try {
                                                    client.send(JSON.stringify({
                                                        type: "ACCOUNT_BANNED",
                                                        message: "Your account was banned by a moderator.",
                                                        reason: reason
                                                    }));
                                                } catch {}

                                                try {
                                                    client.close(4003, "Account banned");
                                                } catch {}
                                            }
                                        });
                                    }
                                );
                            }
                        );
                    });
                });

                return;
            }

            // ====================================================
            // ADMIN ACCOUNT UNBAN
            // ====================================================

            if (type === "ACCOUNT_UNBAN") {
                getAdmin(username, (admin) => {
                    if (!admin) {
                        ws.send(JSON.stringify({
                            type: "ACCOUNT_UNBAN_RESP",
                            success: false,
                            message: "Not authorized."
                        }));

                        return;
                    }

                    const target = String(data.target || "").trim();

                    if (!target) {
                        ws.send(JSON.stringify({
                            type: "ACCOUNT_UNBAN_RESP",
                            success: false,
                            message: "Invalid player."
                        }));

                        return;
                    }

                    db.run(
                        `DELETE FROM account_bans WHERE username=?`,
                        [target],
                        err => {
                            ws.send(JSON.stringify({
                                type: "ACCOUNT_UNBAN_RESP",
                                success: !err,
                                target: target,
                                message: err
                                    ? "Unban failed."
                                    : "Account unbanned."
                            }));
                        }
                    );
                });

                return;
            }
            // ====================================================
            // FRIEND REQUEST
            // ====================================================

            if (type === "FRIEND_REQUEST") {
                const target = data.target;

                if (!target || username === target) {
                    return;
                }

                isBlocked(username, target, (blocked) => {
                    if (blocked) {
                        return;
                    }

                    const [u1, u2] = normalizePair(username, target);

                    db.get(
                        `
                        SELECT 1
                        FROM friends
                        WHERE user1=? AND user2=?
                        `,
                        [u1, u2],
                        (e, row) => {
                            if (row) {
                                return;
                            }

                            db.run(
                                `
                                INSERT OR IGNORE INTO friend_requests
                                VALUES(?,?,?)
                                `,
                                [username, target, Date.now()]
                            );
                        }
                    );
                });

                return;
            }

            // ====================================================
            // FRIEND WITHDRAW
            // ====================================================

            if (type === "FRIEND_WITHDRAW") {
                db.run(
                    `
                    DELETE FROM friend_requests
                    WHERE from_user=? AND to_user=?
                    `,
                    [username, data.target]
                );

                return;
            }

            // ====================================================
            // FRIEND ACCEPT
            // ====================================================

            if (type === "FRIEND_ACCEPT") {
                const target = data.target;

                if (!target || username === target) {
                    return;
                }

                const [u1, u2] = normalizePair(username, target);

                db.get(
                    `
                    SELECT 1
                    FROM friend_requests
                    WHERE from_user=? AND to_user=?
                    `,
                    [target, username],
                    (e, row) => {
                        if (!row) {
                            return;
                        }

                        db.serialize(() => {
                            db.run(
                                `
                                INSERT OR IGNORE INTO friends
                                VALUES(?,?,?)
                                `,
                                [u1, u2, Date.now()]
                            );

                            db.run(
                                `
                                DELETE FROM friend_requests
                                WHERE from_user=? AND to_user=?
                                `,
                                [target, username]
                            );
                        });
                    }
                );

                return;
            }

            // ====================================================
            // FRIEND REJECT
            // ====================================================

            if (type === "FRIEND_REJECT") {
                db.run(
                    `
                    DELETE FROM friend_requests
                    WHERE from_user=? AND to_user=?
                    `,
                    [data.target, username]
                );

                return;
            }

            // ====================================================
            // FRIEND DELETE
            // ====================================================

            if (type === "FRIEND_DELETE") {
                const [u1, u2] = normalizePair(username, data.target);

                db.run(
                    `
                    DELETE FROM friends
                    WHERE user1=? AND user2=?
                    `,
                    [u1, u2]
                );

                return;
            }

            // ====================================================
            // BLOCK ADD
            // ====================================================

            if (type === "BLOCK_ADD") {
                const target = data.target;

                if (!target || username === target) {
                    return;
                }

                db.serialize(() => {
                    db.run(
                        `
                        INSERT OR IGNORE INTO blocks
                        VALUES(?,?,?)
                        `,
                        [username, target, Date.now()]
                    );

                    const [u1, u2] = normalizePair(username, target);

                    db.run(
                        `
                        DELETE FROM friends
                        WHERE user1=? AND user2=?
                        `,
                        [u1, u2]
                    );

                    db.run(
                        `
                        DELETE FROM friend_requests
                        WHERE
                            (from_user=? AND to_user=?)
                            OR
                            (from_user=? AND to_user=?)
                        `,
                        [username, target, target, username]
                    );
                });

                return;
            }

            // ====================================================
            // BLOCK REMOVE
            // ====================================================

            if (type === "BLOCK_REMOVE") {
                db.run(
                    `
                    DELETE FROM blocks
                    WHERE blocker=? AND blocked=?
                    `,
                    [username, data.target]
                );

                return;
            }

            // ====================================================
            // LOAD FRIENDS
            // ====================================================

            if (type === "FRIENDS_LOAD") {
                db.all(
                    `
                    SELECT *
                    FROM friends
                    WHERE user1=? OR user2=?
                    `,
                    [username, username],
                    (e, friends) => {
                        db.all(
                            `
                            SELECT *
                            FROM friend_requests
                            WHERE to_user=?
                            `,
                            [username],
                            (e, requests) => {
                                db.all(
                                    `
                                    SELECT blocked
                                    FROM blocks
                                    WHERE blocker=?
                                    `,
                                    [username],
                                    (e, blocks) => {
                                        ws.send(JSON.stringify({
                                            type: "FRIENDS_LOAD_RESP",
                                            friends: friends || [],
                                            requests: requests || [],
                                            blocks: blocks || []
                                        }));
                                    }
                                );
                            }
                        );
                    }
                );

                return;
            }
            // ====================================================
            // STATS SAVE
            // ====================================================

            if (type === "STATS_SAVE") {
                db.get(
                    `
                    SELECT secret, last_stats_hash
                    FROM users
                    WHERE username=?
                    `,
                    [username],
                    (e, user) => {
                        if (!user) {
                            return;
                        }

                        if (sign(json, user.secret) !== sig) {
                            flag(username, "BAD_SIGNATURE");
                            return;
                        }

                        const newHash = sha(json);

                        if (newHash === user.last_stats_hash) {
                            return;
                        }

                        db.get(
                            `
                            SELECT json
                            FROM player_stats
                            WHERE username=?
                            `,
                            [username],
                            (e, row) => {
                                let oldS = {};
                                let newS;

                                try {
                                    oldS = row ? JSON.parse(row.json) : {};
                                    newS = JSON.parse(json);
                                } catch {
                                    flag(username, "BAD_STATS_JSON");
                                    return;
                                }

                                if (isImpossible(oldS, newS)) {
                                    flag(username, "IMPOSSIBLE_PROGRESS");
                                    return;
                                }

                                db.run(
                                    `
                                    INSERT INTO player_stats(username, json)
                                    VALUES(?,?)
                                    ON CONFLICT(username)
                                    DO UPDATE SET json=excluded.json
                                    `,
                                    [username, json]
                                );

                                db.run(
                                    `
                                    UPDATE users
                                    SET last_stats_hash=?
                                    WHERE username=?
                                    `,
                                    [newHash, username]
                                );

                                // Persistent backup on Railway Volume.
                                try {
                                    fs.writeFileSync(
                                        path.join(BACKUP_DIR, `${username}.json`),
                                        json
                                    );
                                } catch (err) {
                                    console.error(
                                        "❌ Stats backup failed:",
                                        err
                                    );
                                }
                            }
                        );
                    }
                );

                return;
            }
            // ====================================================
            // STATS LOAD
            // ====================================================

            if (type === "STATS_LOAD") {
                db.get(
                    `
                    SELECT secret
                    FROM users
                    WHERE username=?
                    `,
                    [username],
                    (e, u) => {
                        if (!u || u.secret !== secret) {
                            return;
                        }

                        db.get(
                            `
                            SELECT json
                            FROM player_stats
                            WHERE username=?
                            `,
                            [username],
                            (e, row) => {
                                ws.send(JSON.stringify({
                                    type: "STATS_LOAD_RESP",
                                    json: row ? row.json : "{}"
                                }));
                            }
                        );
                    }
                );

                return;
            }

            // ====================================================
            // TIER LOAD
            // ====================================================

            if (type === "TIER_LOAD") {
                db.get(
                    `
                    SELECT json
                    FROM player_stats
                    WHERE username=?
                    `,
                    [username],
                    (e, row) => {
                        let stats = {};

                        try {
                            stats = row ? JSON.parse(row.json) : {};
                        } catch {
                            stats = {};
                        }

                        const tier = computeTier(stats);
                        const tierSignature = sign("TIER_" + tier, secret);

                        ws.send(JSON.stringify({
                            type: "TIER_RESP",
                            tier,
                            sig: tierSignature
                        }));
                    }
                );

                return;
            }

        } // End ws.on("message")
    } // End wss.on("connection")
);

// ============================================================
// WEBSOCKET ERROR HANDLING
// ============================================================

wss.on("error", err => {
    console.error("❌ WebSocket server error:", err);
});

// ============================================================
// HTTP SERVER ERROR HANDLING
// ============================================================

server.on("error", err => {
    console.error("❌ HTTP server error:", err);
});

// ============================================================
// START SERVER
// ============================================================

const PORT = process.env.PORT || 3000;

server.listen(PORT, "0.0.0.0", () => {
    console.log("==========================================");
    console.log("🚀 Auth server running on port", PORT);
    console.log("🌐 Listening on 0.0.0.0");
    console.log("📁 SQLite database:", DB_PATH);
    console.log("👑 Permanent random admin slots:", RANDOM_ADMIN_COUNT);
    console.log("📁 Backups:", BACKUP_DIR);
    console.log("❤️ Health endpoint:", "/health");
    console.log("==========================================");
});

// ============================================================
// GRACEFUL SHUTDOWN
// ============================================================

let shuttingDown = false;

function shutdown(signal) {
    if (shuttingDown) {
        return;
    }

    shuttingDown = true;

    console.log("==========================================");
    console.log(`🛑 ${signal} received.`);
    console.log("🛑 Beginning graceful shutdown...");

    // Stop accepting new HTTP/WebSocket connections.
    server.close(() => {
        console.log("✅ HTTP/WebSocket server closed.");

        // Force SQLite WAL data back into the main database
        // before closing.
        db.run("PRAGMA wal_checkpoint(FULL)", err => {
            if (err) {
                console.error(
                    "⚠️ SQLite WAL checkpoint error:",
                    err.message
                );
            } else {
                console.log("✅ SQLite WAL checkpoint completed.");
            }

            db.close(closeErr => {
                if (closeErr) {
                    console.error("❌ SQLite close error:", closeErr);
                    process.exit(1);
                }

                console.log("✅ SQLite database closed safely.");
                console.log("🛑 Server shutdown complete.");
                console.log("==========================================");

                process.exit(0);
            });
        });
    });

    // Safety timeout: don't leave the container hanging indefinitely.
    setTimeout(() => {
        console.error("⚠️ Forced shutdown after timeout.");
        process.exit(1);
    }, 10000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
