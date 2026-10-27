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
// SERVER-AUTHORITATIVE USERNAME VALIDATION
// ============================================================

const USERNAME_MIN_LENGTH = 3;
const USERNAME_MAX_LENGTH = 20;

// Extend these lists through the hosting environment. They are a moderation
// filter, not a complete hate-speech or impersonation detector.
const DEFAULT_RESTRICTED_USERNAME_TERMS = [
    "admin", "administrator", "support", "root", "moderator", "mod",
    "staff", "system"
];
const DEFAULT_PROTECTED_IDENTITY_TERMS = [
    "staff", "discord", "steam", "playstation", "xbox",
    "roblox", "minecraft", "fortnite", "openai"
];

// EDIT THIS ARRAY to add terms that must not appear in a username.
// These are example profanity terms; replace/add entries to match your game's
// moderation policy. Keep each term in quotes and separate entries with commas.
const DEFAULT_PROHIBITED_USERNAME_TERMS = [
 "fuck",
"cunt",
"nigger",
"spic",
"gook",
"kike"
];

function readUsernameTermList(envName, defaults = []) {
    const configured = String(process.env[envName] || "")
        .split(",")
        .map(term => term.trim())
        .filter(Boolean);
    return [...new Set([...defaults, ...configured].map(term => term.toLocaleLowerCase()))];
}

const RESTRICTED_USERNAME_TERMS = readUsernameTermList(
    "USERNAME_RESTRICTED_TERMS",
    DEFAULT_RESTRICTED_USERNAME_TERMS
);
const PROTECTED_IDENTITY_TERMS = readUsernameTermList(
    "USERNAME_PROTECTED_TERMS",
    DEFAULT_PROTECTED_IDENTITY_TERMS
);

const PROHIBITED_USERNAME_TERMS = readUsernameTermList(
    "USERNAME_PROHIBITED_TERMS",
    DEFAULT_PROHIBITED_USERNAME_TERMS
);

function compactUsername(value) {
    return String(value || "")
        .normalize("NFKC")
        .toLocaleLowerCase()
        .replace(/[\p{P}\p{S}\p{Z}\p{C}_-]+/gu, "");
}

function usernameContainsTerm(compact, term) {
    const normalizedTerm = compactUsername(term);
    return normalizedTerm.length > 0 && compact.includes(normalizedTerm);
}

function validateRegistrationUsername(rawUsername) {
    const username = String(rawUsername || "").trim();
    const length = [...username].length;

    if (!username) {
        return { ok: false, message: "Please enter a username." };
    }
    if (length < USERNAME_MIN_LENGTH) {
        return { ok: false, message: `Username must be at least ${USERNAME_MIN_LENGTH} characters long.` };
    }
    if (length > USERNAME_MAX_LENGTH) {
        return { ok: false, message: `Username must be no more than ${USERNAME_MAX_LENGTH} characters long.` };
    }
    if (/[\p{C}]/u.test(username)) {
        return { ok: false, message: "Username contains unsupported characters. Please choose another username." };
    }

    const compact = compactUsername(username);
    if (RESTRICTED_USERNAME_TERMS.some(term => usernameContainsTerm(compact, term))) {
        return { ok: false, message: "That username contains a restricted system keyword. Please choose another username." };
    }
    if (PROHIBITED_USERNAME_TERMS.some(term => usernameContainsTerm(compact, term))) {
        return { ok: false, message: "That username may violate our community guidelines. Please choose another username." };
    }

 if (PROHIBITED_USERNAME_TERMS.some(
    term => usernameContainsTerm(compact, term)
)) {
    return {
        ok: false,
        message: "That username may violate our community guidelines. Please choose another username."
    };
}
    if (PROTECTED_IDENTITY_TERMS.some(term => usernameContainsTerm(compact, term))) {
        return { ok: false, message: "That username may impersonate a brand, public figure, or official staff member. Please choose another username." };
    }

    return { ok: true, username };
}

function sendRegistrationFailure(ws, message) {
    if (ws.readyState === 1) {
        ws.send(JSON.stringify({
            type: "REGISTER_RESP",
            success: false,
            message
        }));
    }
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

    // Case-insensitive uniqueness prevents duplicate accounts such as Player
    // and player, including when two registration requests arrive together.
    db.run(
        `CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_nocase
         ON users(username COLLATE NOCASE)`,
        err => {
            if (err) {
                console.error(
                    "[USERNAME SECURITY] Could not create case-insensitive username index. " +
                    "Check for existing accounts whose usernames differ only by case:",
                    err.message
                );
            }
        }
    );

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
    // Signature mismatch diagnostics are intentionally silent. Authentication
    // is bound to the logged-in WebSocket session rather than a generic HMAC
    // shared by unrelated message payloads.
    if (reason === "BAD_SIGNATURE") return;

    console.warn("[SECURITY]", username, reason);

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
        `http\://${req.headers.host || "localhost"}`
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
<style>body{font:16px system-ui,sans-serif;max-width:620px;margin:50px auto;padding:0 20px;background:#171717;color:#eee}main{border:1px solid #633;padding:24px;border-radius:12px;background:#222}label{display\:block;margin:18px 0 6px}input{box-sizing\:border-box;width:100%;padding:12px;background:#111;color:#fff;border:1px solid #777;border-radius:6px}button{margin-top:20px;padding:12px 18px;background:#a21d2b;color:#fff;border:0;border-radius:6px;font-weight:700;cursor\:pointer}p{line-height:1.5}.warning{color:#ff9b9b;font-weight:700}</style></head>
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

            const type = String(data.type || "").trim();
            const username = String(data.username || "").trim();
            // Accept both field spellings so clients using camelCase do not
            // accidentally register a NULL password hash and become unable to log in.
            const password_hash = typeof data.password_hash === "string"
                ? data.password_hash
                : (typeof data.passwordHash === "string" ? data.passwordHash : "");
            const json = data.json;
            const sig = data.sig;
            const secret = data.secret;
            const device = data.device;

            if (!type || !username) {
                if (type === "REGISTER" || type === "LOGIN") {
                    ws.send(JSON.stringify({
                        type: type === "REGISTER" ? "REGISTER_RESP" : "LOGIN_RESP",
                        success: false,
                        message: "Enter a username and password."
                    }));
                }
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

            // Registration and login establish identity. All other game
            // messages must arrive on the authenticated WebSocket session.
            // Do not validate a generic HMAC here: message types use different
            // payloads, and comparing every signature to sign(username, secret)
            // incorrectly rejects legitimate requests.
            if (type !== "REGISTER" && type !== "LOGIN") {
                if (!ws.authenticated || ws.username !== username) {
                    // Quietly reject unauthenticated or mismatched requests.
                    return;
                }
            }

            // ====================================================
            // SERVER-AUTHORITATIVE ADMIN STATUS
            // ====================================================

            // Never let REGISTER/LOGIN or an unauthenticated message overwrite
            // the identity bound to an already-authenticated WebSocket.
            if (ws.authenticated && ws.username === username &&
                type !== "REGISTER" && type !== "LOGIN") {
                getAdmin(username, (admin) => {
                    if (!ws.authenticated || ws.username !== username) return;
                    ws.isAdmin = admin;

                    if (ws.adminStatus !== admin) {
                        ws.adminStatus = admin;
                        ws.send(JSON.stringify({
                            type: "ADMIN_STATUS",
                            admin: admin
                        }));
                    }
                });
            }

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
                const usernameValidation = validateRegistrationUsername(username);
                if (!usernameValidation.ok) {
                    sendRegistrationFailure(ws, usernameValidation.message);
                    return;
                }

                const canonicalUsername = usernameValidation.username;
                if (!password_hash || password_hash.length > 512) {
                    sendRegistrationFailure(ws, "A valid password is required.");
                    return;
                }

                // Query the authoritative account database so duplicate names
                // receive a stable response. The unique index is the race guard.
                db.get(
                    `SELECT username FROM users WHERE username = ? COLLATE NOCASE LIMIT 1`,
                    [canonicalUsername],
                    (lookupErr, existingUser) => {
                        if (lookupErr) {
                            console.error("[REGISTER] Username lookup failed:", lookupErr.message);
                            sendRegistrationFailure(ws, "Registration is temporarily unavailable. Please try again.");
                            return;
                        }

                        if (existingUser) {
                            sendRegistrationFailure(ws, "Username already exists. Please choose another username or log in.");
                            return;
                        }

                        const s = makeSecret();
                        db.run(
                            `INSERT INTO users(username, password_hash, secret, device)
                             VALUES(?,?,?,?)`,
                            [canonicalUsername, password_hash, s, device],
                            err => {
                                if (err) {
                                    const usernameExists =
                                        err.code === "SQLITE_CONSTRAINT" &&
                                        (/users\.username/i.test(err.message) ||
                                         /idx_users_username_nocase/i.test(err.message) ||
                                         /UNIQUE constraint failed: users\.username/i.test(err.message));
                                    const message = usernameExists
                                        ? "Username already exists. Please choose another username or log in."
                                        : "Registration failed. Please try again.";

                                    console.error(
                                        "[REGISTER]",
                                        usernameExists ? "Duplicate username:" : "Registration failed:",
                                        canonicalUsername,
                                        err.message
                                    );
                                    sendRegistrationFailure(ws, message);
                                    return;
                                }

                                console.log("Registered user:", canonicalUsername);
                                ensureRandomAdmins();
                                if (ws.readyState === 1) {
                                    ws.send(JSON.stringify({
                                        type: "REGISTER_RESP",
                                        success: true,
                                        secret: s,
                                        message: "Registration successful."
                                    }));
                                }
                            }
                        );
                    }
                );
                return;
            }

            // ====================================================
            // LOGIN
            // ====================================================

            if (type === "LOGIN") {
                // A failed re-login must not retain a prior session identity.
                ws.authenticated = false;
                ws.username = null;
                ws.secret = null;
                ws.isAdmin = false;
                ws.adminStatus = false;

                if (!password_hash || password_hash.length > 512) {
                    ws.send(JSON.stringify({
                        type: "LOGIN_RESP",
                        success: false,
                        message: "Enter a valid username and password."
                    }));
                    return;
                }

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
                            if (e) {
                                console.error("[LOGIN] Account lookup failed:", e.message);
                                ws.send(JSON.stringify({
                                    type: "LOGIN_RESP",
                                    success: false,
                                    message: "Login is temporarily unavailable. Please try again."
                                }));
                                return;
                            }

                            if (!row || row.password_hash !== password_hash) {
                                ws.send(JSON.stringify({
                                    type: "LOGIN_RESP",
                                    success: false,
                                    message: "Incorrect username or password."
                                }));

                                return;
                            }

                            db.get(
                                `SELECT reason FROM account_bans WHERE username=?`,
                                [username],
                                (banErr, banRow) => {
                                    if (banErr) {
                                        console.error("[LOGIN] Account-ban lookup failed:", banErr.message);
                                        ws.send(JSON.stringify({
                                            type: "LOGIN_RESP",
                                            success: false,
                                            message: "Login is temporarily unavailable. Please try again."
                                        }));
                                        return;
                                    }

                                    if (banRow) {
                                        ws.send(JSON.stringify({
                                            type: "LOGIN_RESP",
                                            success: false,
                                            message: "Account banned: " +
                                                (banRow.reason || "Moderator ban")
                                        }));

                                        return;
                                    }

                                    // Historical cheat flags are informational only.
                                    // A login ban must come from account_bans or hwid_bans.

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
                                        ws.secret = row.secret;
                                        ws.authenticated = true;
                                        ws.isAdmin = admin;
                                        ws.adminStatus = admin;

                                        ws.send(JSON.stringify({
                                            type: "LOGIN_RESP",
                                            success: true,
                                            message: "Login successful.",
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

                const pair = normalizePair(username, target);
                const u1 = pair[0];
                const u2 = pair[1];

                db.get(
                    "SELECT 1 FROM friend_requests WHERE from_user = ? AND to_user = ?",
                    [target, username],
                    (err, row) => {
                        if (err) {
                            console.error(
                                "[FRIEND_ACCEPT] Request lookup failed:",
                                err.message
                            );
                            return;
                        }

                        if (!row) {
                            return;
                        }

                        db.run(
                            "INSERT OR IGNORE INTO friends (user1, user2, created_at) VALUES (?, ?, ?)",
                            [u1, u2, Date.now()],
                            insertErr => {
                                if (insertErr) {
                                    console.error(
                                        "[FRIEND_ACCEPT] Friend insert failed:",
                                        insertErr.message
                                    );
                                    return;
                                }

                                db.run(
                                    "DELETE FROM friend_requests WHERE from_user = ? AND to_user = ?",
                                    [target, username],
                                    deleteErr => {
                                        if (deleteErr) {
                                            console.error(
                                                "[FRIEND_ACCEPT] Request deletion failed:",
                                                deleteErr.message
                                            );
                                        }
                                    }
                                );
                            }
                        );
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

                        // The WebSocket session was authenticated at LOGIN.
                        // Validate the stats payload itself instead of rejecting
                        // it based on a client-specific signature representation.
                        if (typeof json !== "string" || json.length > 1_000_000) {
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
                    `SELECT json FROM player_stats WHERE username=?`,
                    [username],
                    (e, row) => {
                        if (e) {
                            console.error("[STATS_LOAD] Database read failed:", e.message);
                            ws.send(JSON.stringify({
                                type: "STATS_LOAD_RESP",
                                success: false,
                                json: "{}"
                            }));
                            return;
                        }

                        ws.send(JSON.stringify({
                            type: "STATS_LOAD_RESP",
                            success: true,
                            json: row ? row.json : "{}"
                        }));
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
                        const tierSignature = sign("TIER_" + tier, ws.secret);

                        ws.send(JSON.stringify({
                            type: "TIER_RESP",
                            tier,
                            sig: tierSignature
                        }));
                    }
                );

                return;
            }
        }); // End ws.on("message")
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
