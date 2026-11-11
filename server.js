const http = require("http");
const { WebSocketServer } = require("ws");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const { domainToASCII } = require("url");

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

    // Additive migrations for accounts created before email recovery existed.
    // Duplicate-column errors are expected on later server starts.
    db.run("ALTER TABLE users ADD COLUMN email TEXT", err => {
        if (err && !/duplicate column name/i.test(err.message))
            console.error("[EMAIL DB] Could not add users.email:", err.message);
    });
    db.run("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0", err => {
        if (err && !/duplicate column name/i.test(err.message))
            console.error("[EMAIL DB] Could not add users.email_verified:", err.message);
    });

    db.run(
        `CREATE UNIQUE INDEX IF NOT EXISTS idx_users_verified_email_nocase
         ON users(email COLLATE NOCASE)
         WHERE email IS NOT NULL AND email_verified = 1`,
        err => {
            if (err) console.error("[EMAIL DB] Could not create verified-email uniqueness index:", err.message);
        }
    );

    db.run(`
        CREATE TABLE IF NOT EXISTS registration_email_challenges (
            challenge_id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            device TEXT,
            code_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            consumed_at INTEGER
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS recovery_email_challenges (
            recovery_id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            used_at INTEGER
        )
    `);
    db.run(`CREATE INDEX IF NOT EXISTS idx_registration_email_challenges_lookup
            ON registration_email_challenges(username, email, expires_at)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_recovery_email_challenges_lookup
            ON recovery_email_challenges(email, created_at, expires_at)`);

    db.run(`
        CREATE TABLE IF NOT EXISTS email_api_rate_limits (
            rate_key TEXT PRIMARY KEY,
            window_started_at INTEGER NOT NULL,
            hit_count INTEGER NOT NULL
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

async function deletePlayerAccountAndData(usernameInput) {
    const requestedUsername = String(usernameInput || "").trim();
    if (!requestedUsername || requestedUsername.length > 20) {
        throw new Error("A valid username is required.");
    }

    // Resolve the exact stored username, but allow the admin to enter any case.
    const account = await dbGetAsync(
        "SELECT username FROM users WHERE username = ? COLLATE NOCASE LIMIT 1",
        [requestedUsername]
    );

    if (!account) {
        return { deleted: false, username: requestedUsername };
    }

    const username = account.username;
    const usernameLower = username.toLocaleLowerCase();

    // Capture the account's stored device before deleting its user row.
    const accountRow = await dbGetAsync(
        "SELECT device FROM users WHERE username = ?",
        [username]
    );

    // Delete every row that refers to this account. Reports are removed both
    // when this player filed the report and when this player was reported.
    const statements = [
        ["DELETE FROM player_stats WHERE username = ?", [username]],
        ["DELETE FROM friends WHERE user1 = ? OR user2 = ?", [username, username]],
        ["DELETE FROM friend_requests WHERE from_user = ? OR to_user = ?", [username, username]],
        ["DELETE FROM blocks WHERE blocker = ? OR blocked = ?", [username, username]],
        ["DELETE FROM reports WHERE reporter = ? OR target = ?", [username, username]],
        ["DELETE FROM account_bans WHERE username = ?", [username]],
        ["DELETE FROM moderators WHERE username = ?", [username]],
        ["DELETE FROM trusted_devices WHERE username = ?", [username]],
        ["DELETE FROM registration_email_challenges WHERE username = ? COLLATE NOCASE", [username]],
        ["DELETE FROM recovery_email_challenges WHERE username = ? COLLATE NOCASE", [username]],
        ["DELETE FROM email_api_rate_limits WHERE rate_key = ?", [`login-account:${usernameLower}`]],
        ["DELETE FROM users WHERE username = ?", [username]]
    ];

    await runDatabaseStatement("BEGIN IMMEDIATE TRANSACTION");
    try {
        for (const [sql, params] of statements) {
            await dbRunAsync(sql, params);
        }
        await runDatabaseStatement("COMMIT");
    } catch (err) {
        try { await runDatabaseStatement("ROLLBACK"); } catch {}
        throw err;
    }

    // Remove the player's individual JSON stat backup, if one exists.
    // Usernames are validated at registration; basename check adds a second
    // safeguard so a crafted input can never address a file outside BACKUP_DIR.
    const backupName = `${username}.json`;
    if (path.basename(backupName) === backupName) {
        const backupPath = path.join(BACKUP_DIR, backupName);
        try {
            if (fs.existsSync(backupPath) && fs.statSync(backupPath).isFile()) {
                fs.unlinkSync(backupPath);
            }
        } catch (err) {
            console.error(`[ADMIN DELETE] Could not remove stat backup for ${username}:`, err.message);
            throw new Error("The database account was deleted, but its stat backup could not be removed. Check the server logs.");
        }
    }

    // Close every live session for the deleted account so it cannot continue
    // playing or recreate account data using an already-authenticated socket.
    if (typeof wss !== "undefined") {
        wss.clients.forEach(client => {
            if (String(client.username || "").toLocaleLowerCase() === usernameLower) {
                try { client.close(4001, "Your account was deleted by the server administrator."); } catch {}
            }
        });
    }

    // Do not remove a matching HWID ban: those are device-wide moderation
    // records and may intentionally apply to other accounts on the same device.
    return { deleted: true, username, device: accountRow ? accountRow.device : null };
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
        "registration_email_challenges",
        "recovery_email_challenges",
        "email_api_rate_limits",
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

// ============================================================
// EMAIL VERIFICATION / PASSWORD RECOVERY API
// ============================================================
// Requires `npm install nodemailer` and server environment variables:
// SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM,
// EMAIL_TOKEN_PEPPER (a long random secret, not stored in the client).
// No recipient-domain allowlist is used; delivery is delegated to the SMTP relay.

let nodemailer = null;
try {
    nodemailer = require("nodemailer");
} catch (err) {
    console.error("[EMAIL] nodemailer is not installed. Run: npm install nodemailer");
}

const EMAIL_TOKEN_PEPPER = process.env.EMAIL_TOKEN_PEPPER || "";
const EMAIL_CODE_TTL_MS = 15 * 60 * 1000;
const EMAIL_MAX_CODE_ATTEMPTS = 5;
const GENERIC_RECOVERY_MESSAGE = "If an account exists, instructions have been sent";
const SMTP_HOST = process.env.SMTP_HOST || "";
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_USER = process.env.SMTP_USER || "";
const SMTP_PASS = process.env.SMTP_PASS || "";
const SMTP_FROM = process.env.SMTP_FROM || "";
const SMTP_SECURE = String(process.env.SMTP_SECURE || "").toLowerCase() === "true" || SMTP_PORT === 465;
let emailTransporter = null;
let nextEmailRateLimitCleanupAt = 0;

const EMAIL_API_PATHS = new Set([
    "/auth/registration/email/start",
    "/auth/registration/email/verify",
    "/auth/recovery/request",
    "/auth/recovery/reset"
]);

function emailApiJson(res, status, payload) {
    if (res.headersSent || res.destroyed) return;
    res.writeHead(status, {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store, max-age=0",
        "Pragma": "no-cache",
        "X-Content-Type-Options": "nosniff"
    });
    res.end(JSON.stringify(payload));
}

function getEmailTransporter() {
    if (emailTransporter) return emailTransporter;
    if (!nodemailer || !SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS || !SMTP_FROM || !EMAIL_TOKEN_PEPPER) {
        return null;
    }

    emailTransporter = nodemailer.createTransport({
        host: SMTP_HOST,
        port: SMTP_PORT,
        secure: SMTP_SECURE,
        auth: { user: SMTP_USER, pass: SMTP_PASS },
        requireTLS: !SMTP_SECURE,
        connectionTimeout: 15000,
        greetingTimeout: 15000,
        socketTimeout: 20000,
        tls: { minVersion: "TLSv1.2" }
    });
    return emailTransporter;
}

function emailServiceReady() {
    return !!getEmailTransporter();
}

async function sendAccountEmail(to, subject, text) {
    const transporter = getEmailTransporter();
    if (!transporter) throw new Error("Email delivery is not configured on the server.");
    await transporter.sendMail({
        from: SMTP_FROM,
        to,
        subject,
        text
    });
}

function normalizeEmailAddress(value) {
    const email = String(value || "").trim();
    if (email.length < 3 || email.length > 254 || /[\s<>]/.test(email)) return null;
    const at = email.lastIndexOf("@");
    if (at <= 0 || at === email.length - 1) return null;
    const local = email.slice(0, at);
    const rawDomain = email.slice(at + 1);
    const domain = domainToASCII(rawDomain);
    if (!domain || local.length > 64 || domain.length > 253 || !domain.includes(".")) return null;
    if (!/^[^@]+$/.test(local) || !/^[A-Za-z0-9.-]+$/.test(domain)) return null;
    const labels = domain.split(".");
    if (labels.some(label => !label || label.length > 63 ||
        label.startsWith("-") || label.endsWith("-") || !/^[A-Za-z0-9-]+$/.test(label))) return null;
    return (local + "@" + domain).toLowerCase();
}

function isValidPasswordHash(value) {
    if (typeof value !== "string" || value.length > 128) return false;
    try {
        const decoded = Buffer.from(value, "base64");
        return decoded.length === 32 && decoded.toString("base64") === value;
    } catch {
        return false;
    }
}

function makeEmailCode() {
    return String(crypto.randomInt(100000, 1000000));
}

function makeEmailChallengeId() {
    return crypto.randomBytes(32).toString("hex");
}

function hashEmailCode(purpose, challengeId, code) {
    if (!EMAIL_TOKEN_PEPPER) throw new Error("EMAIL_TOKEN_PEPPER is not configured.");
    return crypto.createHmac("sha256", EMAIL_TOKEN_PEPPER)
        .update(`${purpose}|${challengeId}|${code}`, "utf8")
        .digest("hex");
}

function constantTimeHexEquals(a, b) {
    if (typeof a !== "string" || typeof b !== "string" || !/^[a-f0-9]{64}$/i.test(a) || !/^[a-f0-9]{64}$/i.test(b)) {
        return false;
    }
    const left = Buffer.from(a, "hex");
    const right = Buffer.from(b, "hex");
    return left.length === right.length && crypto.timingSafeEqual(left, right);
}

async function emailRateLimitAllowed(key, maximum, windowMs) {
    const now = Date.now();
    const storedKey = sha(String(key || "unknown"));
    const result = await dbRunAsync(
        `INSERT INTO email_api_rate_limits(rate_key, window_started_at, hit_count)
         VALUES(?, ?, 1)
         ON CONFLICT(rate_key) DO UPDATE SET
            window_started_at = CASE
                WHEN ? - email_api_rate_limits.window_started_at >= ? THEN ?
                ELSE email_api_rate_limits.window_started_at
            END,
            hit_count = CASE
                WHEN ? - email_api_rate_limits.window_started_at >= ? THEN 1
                ELSE email_api_rate_limits.hit_count + 1
            END
         WHERE ? - email_api_rate_limits.window_started_at >= ?
            OR email_api_rate_limits.hit_count < ?`,
        [
            storedKey, now,
            now, windowMs, now,
            now, windowMs,
            now, windowMs, maximum
        ]
    );

    if (now >= nextEmailRateLimitCleanupAt) {
        nextEmailRateLimitCleanupAt = now + 6 * 60 * 60 * 1000;
        Promise.all([
            dbRunAsync("DELETE FROM email_api_rate_limits WHERE window_started_at < ?", [now - 48 * 60 * 60 * 1000]),
            dbRunAsync("DELETE FROM registration_email_challenges WHERE expires_at <= ? OR consumed_at IS NOT NULL", [now]),
            dbRunAsync("DELETE FROM recovery_email_challenges WHERE expires_at <= ? OR used_at IS NOT NULL", [now])
        ]).catch(err => console.error("[EMAIL] Expired challenge/rate-limit cleanup failed:", err.message));
    }

    return result.changes === 1;
}

function requestClientIp(req) {
    // Railway's edge proxy supplies X-Forwarded-For. The first value is the
    // originating client address when the deployment proxy overwrites it.
    const forwarded = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
    return forwarded || req.socket.remoteAddress || "unknown";
}

function isSecureEmailRequest(req) {
    const forwardedProto = String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim().toLowerCase();
    const host = String(req.headers.host || "").toLowerCase();
    const localHost = host.startsWith("localhost") || host.startsWith("127.0.0.1") || host.startsWith("[::1]");
    return forwardedProto === "https" || (!forwardedProto && localHost);
}

function readEmailJsonBody(req, maximumBytes = 16384) {
    return new Promise((resolve, reject) => {
        let body = "";
        let total = 0;
        let tooLarge = false;
        req.on("data", chunk => {
            total += chunk.length;
            if (total > maximumBytes) {
                tooLarge = true;
                body = "";
                return;
            }
            if (!tooLarge) body += chunk.toString("utf8");
        });
        req.on("end", () => {
            if (tooLarge) {
                reject(Object.assign(new Error("Request body too large."), { statusCode: 413 }));
                return;
            }
            try {
                resolve(JSON.parse(body || "{}"));
            } catch {
                reject(Object.assign(new Error("Invalid JSON request body."), { statusCode: 400 }));
            }
        });
        req.on("error", reject);
    });
}

function dbGetAsync(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => err ? reject(err) : resolve(row || null));
    });
}

function dbRunAsync(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function (err) {
            if (err) reject(err);
            else resolve({ changes: this.changes, lastID: this.lastID });
        });
    });
}

function escapeEmailText(value) {
    return String(value || "").replace(/[\r\n\t]/g, " ").slice(0, 254);
}

async function startRegistrationEmail(body, req, res) {
    const usernameValidation = validateRegistrationUsername(body.username);
    const email = normalizeEmailAddress(body.email);
    const passwordHash = body.passwordHash;
    const device = String(body.device || "").slice(0, 255);

    if (!usernameValidation.ok) {
        emailApiJson(res, 400, { success: false, message: usernameValidation.message });
        return;
    }
    if (!email || !isValidPasswordHash(passwordHash)) {
        emailApiJson(res, 400, { success: false, message: "Enter a valid email address and registration details." });
        return;
    }
    if (!emailServiceReady()) {
        console.error("[EMAIL] Registration verification is disabled: configure nodemailer, SMTP settings, and EMAIL_TOKEN_PEPPER.");
        emailApiJson(res, 503, { success: false, message: "Email verification is temporarily unavailable. Please try again later." });
        return;
    }

    const ip = requestClientIp(req);
    if (!(await emailRateLimitAllowed(`reg-ip:${ip}`, 8, 60 * 60 * 1000)) ||
        !(await emailRateLimitAllowed(`reg-email:${sha(email)}`, 4, 60 * 60 * 1000))) {
        emailApiJson(res, 429, { success: false, message: "Too many verification requests. Please try again later." });
        return;
    }

    const username = usernameValidation.username;
    const existing = await dbGetAsync(
        `SELECT username FROM users
         WHERE username = ? COLLATE NOCASE
            OR (email = ? COLLATE NOCASE AND COALESCE(email_verified, 0) = 1)
         LIMIT 1`,
        [username, email]
    );
    if (existing) {
        emailApiJson(res, 409, { success: false, message: "That username or verified email address is already associated with an account." });
        return;
    }

    const challengeId = makeEmailChallengeId();
    const code = makeEmailCode();
    const now = Date.now();
    const expiresAt = now + EMAIL_CODE_TTL_MS;
    const codeHash = hashEmailCode("registration", challengeId, code);

    await dbRunAsync(
        `DELETE FROM registration_email_challenges
         WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE OR expires_at <= ?`,
        [username, email, now]
    );
    await dbRunAsync(
        `INSERT INTO registration_email_challenges
         (challenge_id, username, email, password_hash, device, code_hash, created_at, expires_at, attempts, consumed_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, NULL)`,
        [challengeId, username, email, passwordHash, device, codeHash, now, expiresAt]
    );

    try {
        await sendAccountEmail(
            email,
            "Wasteland Arena — verify your email",
            `Hello ${escapeEmailText(username)},\n\nYour Wasteland Arena email verification code is: ${code}\n\nThis code expires in 15 minutes and can only be used once. If you did not try to register, you can ignore this message.`
        );
    } catch (err) {
        console.error("[EMAIL] Registration verification delivery failed:", err.message);
        await dbRunAsync("DELETE FROM registration_email_challenges WHERE challenge_id = ?", [challengeId]);
        emailApiJson(res, 503, { success: false, message: "We could not send the verification email. Please try again later." });
        return;
    }

    emailApiJson(res, 200, {
        success: true,
        challengeId,
        message: "Verification code sent."
    });
}

async function verifyRegistrationEmail(body, req, res) {
    const ip = requestClientIp(req);
    if (!(await emailRateLimitAllowed(`reg-verify-ip:${ip}`, 40, 60 * 60 * 1000))) {
        emailApiJson(res, 429, { success: false, message: "Too many verification attempts. Request a new code later." });
        return;
    }

    const challengeId = String(body.challengeId || "").trim();
    const code = String(body.code || "").trim();
    if (!/^[a-f0-9]{64}$/i.test(challengeId) || !/^\d{6}$/.test(code)) {
        emailApiJson(res, 400, { success: false, message: "The verification code is invalid or expired. Request a new code." });
        return;
    }

    const row = await dbGetAsync(
        `SELECT * FROM registration_email_challenges WHERE challenge_id = ? AND consumed_at IS NULL`,
        [challengeId]
    );
    const now = Date.now();
    if (!row || row.expires_at <= now || row.attempts >= EMAIL_MAX_CODE_ATTEMPTS) {
        emailApiJson(res, 400, { success: false, message: "The verification code is invalid or expired. Request a new code." });
        return;
    }

    const expectedHash = hashEmailCode("registration", challengeId, code);
    if (!constantTimeHexEquals(expectedHash, row.code_hash)) {
        await dbRunAsync(
            `UPDATE registration_email_challenges
             SET attempts = attempts + 1
             WHERE challenge_id = ? AND consumed_at IS NULL AND attempts < ?`,
            [challengeId, EMAIL_MAX_CODE_ATTEMPTS]
        );
        emailApiJson(res, 400, { success: false, message: "The verification code is incorrect or expired." });
        return;
    }

    // Consume before account creation. The username/email unique indexes and
    // conditional consume make replayed or simultaneous code submissions fail.
    const consumed = await dbRunAsync(
        `UPDATE registration_email_challenges
         SET consumed_at = ?
         WHERE challenge_id = ? AND consumed_at IS NULL AND expires_at > ? AND attempts < ? AND code_hash = ?`,
        [now, challengeId, now, EMAIL_MAX_CODE_ATTEMPTS, expectedHash]
    );
    if (consumed.changes !== 1) {
        emailApiJson(res, 400, { success: false, message: "The verification code is invalid, expired, or already used." });
        return;
    }

    const secret = makeSecret();
    try {
        await dbRunAsync(
            `INSERT INTO users(username, password_hash, secret, device, email, email_verified)
             VALUES(?, ?, ?, ?, ?, 1)`,
            [row.username, row.password_hash, secret, row.device, row.email]
        );
    } catch (err) {
        const duplicate = /UNIQUE constraint failed/i.test(err.message || "");
        console.error("[EMAIL REGISTER] Account creation failed:", err.message);
        emailApiJson(res, duplicate ? 409 : 500, {
            success: false,
            message: duplicate
                ? "That username or email address is already associated with an account."
                : "Registration could not be completed. Please start again."
        });
        return;
    }

    console.log("[EMAIL REGISTER] Verified recovery email and registered account:", row.username);
    ensureRandomAdmins();
    emailApiJson(res, 200, {
        success: true,
        username: row.username,
        message: "Registration successful. Recovery email verified."
    });
}

async function requestPasswordRecovery(body, req, res) {
    // Keep the response identical for unknown, unverified, and known addresses.
    // The email work runs after the generic HTTP response so SMTP delivery time
    // does not expose whether an account matched the address.
    const ip = requestClientIp(req);
    const email = normalizeEmailAddress(body.email);
    if (!email) {
        emailApiJson(res, 200, { success: true, message: GENERIC_RECOVERY_MESSAGE });
        return;
    }

    const allowed =
        (await emailRateLimitAllowed(`recovery-ip:${ip}`, 10, 60 * 60 * 1000)) &&
        (await emailRateLimitAllowed(`recovery-email:${sha(email)}`, 3, 60 * 60 * 1000));
    if (!allowed) {
        emailApiJson(res, 200, { success: true, message: GENERIC_RECOVERY_MESSAGE });
        return;
    }

    const user = await dbGetAsync(
        `SELECT username, email FROM users
         WHERE email = ? COLLATE NOCASE AND COALESCE(email_verified, 0) = 1
         LIMIT 1`,
        [email]
    );

    if (user) {
        setImmediate(async () => {
            try {
                const recoveryId = makeEmailChallengeId();
                const code = makeEmailCode();
                const now = Date.now();
                const codeHash = hashEmailCode("recovery", recoveryId, code);

                await dbRunAsync(
                    `DELETE FROM recovery_email_challenges
                     WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE OR expires_at <= ?`,
                    [user.username, email, now]
                );
                await dbRunAsync(
                    `INSERT INTO recovery_email_challenges
                     (recovery_id, username, email, code_hash, created_at, expires_at, attempts, used_at)
                     VALUES (?, ?, ?, ?, ?, ?, 0, NULL)`,
                    [recoveryId, user.username, user.email, codeHash, now, now + EMAIL_CODE_TTL_MS]
                );

                await sendAccountEmail(
                    user.email,
                    "Wasteland Arena — account recovery",
                    `A password-recovery request was made for your Wasteland Arena account.\n\nUsername: ${escapeEmailText(user.username)}\nPassword reset code: ${code}\n\nThe code expires in 15 minutes and can only be used once. If you did not request this, ignore this message and do not share the code with anyone.`
                );
            } catch (err) {
                console.error("[EMAIL RECOVERY] Recovery email processing/delivery failed:", err.message);
            }
        });
    }

    emailApiJson(res, 200, { success: true, message: GENERIC_RECOVERY_MESSAGE });
}

async function resetPasswordWithRecoveryCode(body, req, res) {
    const ip = requestClientIp(req);
    if (!(await emailRateLimitAllowed(`recovery-reset-ip:${ip}`, 40, 60 * 60 * 1000))) {
        emailApiJson(res, 429, { success: false, message: "Too many reset attempts. Please try again later." });
        return;
    }

    const email = normalizeEmailAddress(body.email);
    const code = String(body.code || "").trim();
    const newPasswordHash = body.newPasswordHash;

    if (!email || !/^\d{6}$/.test(code) || !isValidPasswordHash(newPasswordHash)) {
        emailApiJson(res, 400, { success: false, message: "The recovery code or new password is invalid." });
        return;
    }

    const row = await dbGetAsync(
        `SELECT * FROM recovery_email_challenges
         WHERE email = ? COLLATE NOCASE AND used_at IS NULL
         ORDER BY created_at DESC LIMIT 1`,
        [email]
    );
    const now = Date.now();

    if (!row || row.expires_at <= now || row.attempts >= EMAIL_MAX_CODE_ATTEMPTS) {
        emailApiJson(res, 400, { success: false, message: "The recovery code is invalid or expired. Request a new code." });
        return;
    }

    const expectedHash = hashEmailCode("recovery", row.recovery_id, code);
    if (!constantTimeHexEquals(expectedHash, row.code_hash)) {
        await dbRunAsync(
            `UPDATE recovery_email_challenges
             SET attempts = attempts + 1
             WHERE recovery_id = ? AND used_at IS NULL AND attempts < ?`,
            [row.recovery_id, EMAIL_MAX_CODE_ATTEMPTS]
        );
        emailApiJson(res, 400, { success: false, message: "The recovery code is incorrect or expired." });
        return;
    }

    const consumed = await dbRunAsync(
        `UPDATE recovery_email_challenges
         SET used_at = ?
         WHERE recovery_id = ? AND used_at IS NULL AND expires_at > ? AND attempts < ? AND code_hash = ?`,
        [now, row.recovery_id, now, EMAIL_MAX_CODE_ATTEMPTS, expectedHash]
    );
    if (consumed.changes !== 1) {
        emailApiJson(res, 400, { success: false, message: "The recovery code is invalid, expired, or already used." });
        return;
    }

    const newSecret = makeSecret();
    const changed = await dbRunAsync(
        `UPDATE users
         SET password_hash = ?, secret = ?
         WHERE username = ? AND email = ? COLLATE NOCASE AND COALESCE(email_verified, 0) = 1`,
        [newPasswordHash, newSecret, row.username, row.email]
    );
    if (changed.changes !== 1) {
        console.error("[EMAIL RECOVERY] Account credential update failed after code validation for:", row.username);
        emailApiJson(res, 500, { success: false, message: "Password reset could not be completed. Please request a new recovery code." });
        return;
    }

    // Revoke remembered-device registrations and active WebSocket sessions.
    await dbRunAsync("DELETE FROM trusted_devices WHERE username = ?", [row.username]);
    await dbRunAsync("DELETE FROM recovery_email_challenges WHERE username = ?", [row.username]);

    if (typeof wss !== "undefined") {
        wss.clients.forEach(client => {
            if (client.username === row.username) {
                try { client.close(4001, "Account password changed; please sign in again."); } catch {}
            }
        });
    }

    let notificationSent = false;
    try {
        await sendAccountEmail(
            row.email,
            "Wasteland Arena — your password was changed",
            `The password for your Wasteland Arena account (${escapeEmailText(row.username)}) was successfully changed.\n\nIf you did not make this change, contact game support immediately and secure the email account associated with your profile.`
        );
        notificationSent = true;
    } catch (err) {
        console.error("[EMAIL RECOVERY] Password-changed notification delivery failed:", err.message);
    }

    emailApiJson(res, 200, {
        success: true,
        username: row.username,
        message: notificationSent
            ? "Password reset successful. A password-change notification was sent to your verified email address."
            : "Password reset successful, but the password-change notification could not be delivered. Please contact support if you did not make this change."
    });
}

async function handleEmailApiRequest(req, res, pathname) {
    if (req.method !== "POST") {
        emailApiJson(res, 405, { success: false, message: "Method not allowed." });
        return;
    }

    if (!isSecureEmailRequest(req)) {
        emailApiJson(res, 426, { success: false, message: "Email account operations require HTTPS." });
        return;
    }

    if (!String(req.headers["content-type"] || "").toLowerCase().startsWith("application/json")) {
        emailApiJson(res, 415, { success: false, message: "Content-Type must be application/json." });
        return;
    }

    try {
        const body = await readEmailJsonBody(req);
        switch (pathname) {
            case "/auth/registration/email/start":
                await startRegistrationEmail(body, req, res);
                return;
            case "/auth/registration/email/verify":
                await verifyRegistrationEmail(body, req, res);
                return;
            case "/auth/recovery/request":
                if (!emailServiceReady()) {
                    emailApiJson(res, 503, { success: false, message: "The email service is temporarily unavailable." });
                    return;
                }
                await requestPasswordRecovery(body, req, res);
                return;
            case "/auth/recovery/reset":
                await resetPasswordWithRecoveryCode(body, req, res);
                return;
            default:
                emailApiJson(res, 404, { success: false, message: "Not found." });
                return;
        }
    } catch (err) {
        console.error("[EMAIL API] Request failed:", err.message);
        emailApiJson(res, err.statusCode || 500, {
            success: false,
            message: err.statusCode === 400
                ? "Invalid request."
                : "The email service is temporarily unavailable. Please try again later."
        });
    }
}

const server = http.createServer((req, res) => {
    const requestUrl = new URL(
        req.url,
        `http\://${req.headers.host || "localhost"}`
    );

    if (EMAIL_API_PATHS.has(requestUrl.pathname)) {
        handleEmailApiRequest(req, res, requestUrl.pathname);
        return;
    }

    if (requestUrl.pathname === "/health" && req.method === "GET") {
        res.writeHead(200, {
            "Content-Type": "text/plain; charset=utf-8"
        });

        res.end("OK");
        return;
    }

    // ============================================================
    // ADMIN: DELETE ONE PLAYER ACCOUNT
    // Uses the same private ADMIN_RESET_TOKEN as the full database reset.
    // This page is administrator-only; players have no self-service route.
    // ============================================================

    if (requestUrl.pathname === "/admin/delete-account" && req.method === "GET") {
        if (!ADMIN_RESET_TOKEN) {
            res.writeHead(503, { "Content-Type": "text/plain; charset=utf-8" });
            res.end("Account deletion is disabled. Set ADMIN_RESET_TOKEN in the server environment to enable administrator tools.");
            return;
        }

        res.writeHead(200, {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff"
        });
        res.end(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Wasteland Arena — Delete Player Account</title>
<style>body{font:16px system-ui,sans-serif;max-width:620px;margin:50px auto;padding:0 20px;background:#171717;color:#eee}main{border:1px solid #633;padding:24px;border-radius:12px;background:#222}label{display:block;margin:18px 0 6px}input{box-sizing:border-box;width:100%;padding:12px;background:#111;color:#fff;border:1px solid #777;border-radius:6px}button{margin-top:20px;padding:12px 18px;background:#a21d2b;color:#fff;border:0;border-radius:6px;font-weight:700;cursor:pointer}p{line-height:1.5}.warning{color:#ff9b9b;font-weight:700}a{color:#9cf}</style></head>
<body><main><h1>Delete one player account</h1>
<p class="warning">This permanently deletes the selected player's account and associated player data. This cannot be undone.</p>
<p>It removes their account, saved stats and JSON backup, friendships, friend requests, blocks, reports filed by or against them, account ban, moderator assignment, trusted devices, email verification/recovery challenges, and active sessions. It does not delete other players' data or the database schema.</p>
<form method="post" action="/admin/delete-account" onsubmit="return confirm('FINAL WARNING: permanently delete this player account and all associated data?');">
<label for="token">Admin reset token</label><input id="token" name="token" type="password" autocomplete="current-password" required>
<label for="username">Exact player username</label><input id="username" name="username" maxlength="20" autocomplete="off" required>
<label for="confirmation">Type DELETE followed by the exact username</label><input id="confirmation" name="confirmation" autocomplete="off" required>
<button type="submit">DELETE THIS PLAYER ACCOUNT</button></form>
<p><a href="/admin/reset">Back to database reset page</a></p></main></body></html>`);
        return;
    }

    if (requestUrl.pathname === "/admin/delete-account" && req.method === "POST") {
        if (!ADMIN_RESET_TOKEN) {
            res.writeHead(503, { "Content-Type": "text/plain; charset=utf-8" });
            res.end("Account deletion is disabled.");
            return;
        }

        let body = "";
        let tooLarge = false;
        req.on("data", chunk => {
            body += chunk.toString("utf8");
            if (body.length > 8192) {
                tooLarge = true;
                res.writeHead(413, { "Content-Type": "text/plain; charset=utf-8" });
                res.end("Request too large.");
                req.destroy();
            }
        });

        req.on("end", async () => {
            if (tooLarge) return;
            const form = new URLSearchParams(body);
            const token = form.get("token") || "";
            const username = String(form.get("username") || "").trim();
            const confirmation = form.get("confirmation") || "";

            if (!safeTokenEquals(token, ADMIN_RESET_TOKEN)) {
                res.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" });
                res.end("Forbidden: invalid admin reset token.");
                return;
            }
            if (!username || username.length > 20 || confirmation !== `DELETE ${username}`) {
                res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
                res.end("Deletion cancelled: enter the exact username and type DELETE followed by that exact username.");
                return;
            }

            try {
                const result = await deletePlayerAccountAndData(username);
                res.writeHead(result.deleted ? 200 : 404, {
                    "Content-Type": "text/html; charset=utf-8",
                    "Cache-Control": "no-store",
                    "X-Content-Type-Options": "nosniff"
                });
                if (result.deleted) {
                    console.warn(`[ADMIN DELETE] Account and associated data deleted: ${result.username}`);
                    res.end(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Account deleted</title></head><body style="font:16px system-ui;max-width:620px;margin:50px auto;padding:0 20px;background:#171717;color:#eee"><h1>Player account deleted</h1><p>Account <strong>${escapeEmailText(result.username).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}</strong> and its associated database records and stat backup were deleted.</p><p><a style="color:#9cf" href="/admin/delete-account">Delete another account</a></p></body></html>`);
                } else {
                    res.end("<!doctype html><html><head><meta charset='utf-8'><title>Account not found</title></head><body style='font:16px system-ui;max-width:620px;margin:50px auto;padding:0 20px;background:#171717;color:#eee'><h1>Account not found</h1><p>No account matched that username. No data was deleted.</p><p><a style='color:#9cf' href='/admin/delete-account'>Return</a></p></body></html>");
                }
            } catch (err) {
                console.error("[ADMIN DELETE] Failed:", err);
                res.writeHead(500, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
                res.end("Account deletion failed. Check the server logs. Database changes are rolled back if the deletion transaction fails.");
            }
        });
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
<p><a href="/admin/delete-account" style="color:#9cf">Delete one player's account instead</a></p>
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
    (ws, request) => {
        ws.clientIp = request ? requestClientIp(request) : "unknown";
        console.log("🔌 WebSocket client connected");

        // ====================================================
        // MESSAGE
        // ====================================================

        ws.on("message", async (msg) => {
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

                // Server-side login throttling is independent of the Unity UI's
                // three-failure recovery prompt. Counters persist in SQLite.
                try {
                    const ipAllowed = await emailRateLimitAllowed(
                        `login-ip:${ws.clientIp || "unknown"}`,
                        30,
                        60 * 1000
                    );
                    const accountAllowed = await emailRateLimitAllowed(
                        `login-account:${username.toLocaleLowerCase()}`,
                        20,
                        15 * 60 * 1000
                    );

                    if (!ipAllowed || !accountAllowed) {
                        ws.send(JSON.stringify({
                            type: "LOGIN_RESP",
                            success: false,
                            message: "Too many login attempts. Please wait before trying again."
                        }));
                        return;
                    }
                } catch (rateLimitErr) {
                    console.error("[LOGIN] Rate-limit check failed:", rateLimitErr.message);
                    ws.send(JSON.stringify({
                        type: "LOGIN_RESP",
                        success: false,
                        message: "Login is temporarily unavailable. Please try again."
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
