const http = require("http");
const { WebSocketServer } = require("ws");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

// Random permanent community-admin slots.
// Change this one number if you want more/fewer admins.
const RANDOM_ADMIN_COUNT = 7;

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

const BACKUP_DIR =
path.join(
DB_DIR,
"backups"
);

if (!fs.existsSync(BACKUP_DIR)) {

    fs.mkdirSync(
        BACKUP_DIR,
        { recursive: true }
    );

}

// ============================================================
// STORAGE PATHS
// ============================================================

const DB_PATH =
path.join(
DB_DIR,
"users.db"
);

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
    .createHmac(
        "sha256",
        secret
    )
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
                                if (!insertErr)
                                    console.log("👑 Random admin selected:", player.username);
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

function broadcastPresence(
username,
online,
state
) {

wss.clients.forEach(c => {

    if (c.readyState === 1) {

        c.send(
            JSON.stringify({
                type: "PRESENCE_UPDATE",
                username,
                online,
                state
            })
        );

    }

});

}

// ============================================================
// SQLITE
// ============================================================

const db =
new sqlite3.Database(
DB_PATH,
(err) => {

        if (err) {

            console.error(
                "❌ SQLite database failed to open:"
            );

            console.error(err);

            process.exit(1);

        }


        console.log(
            "✅ SQLite database opened:"
        );

        console.log(DB_PATH);

    }
);

// ============================================================
// SQLITE PERFORMANCE / SAFETY
// ============================================================

db.serialize(() => {

db.run(
    "PRAGMA journal_mode = WAL",
    err => {

        if (err) {

            console.error(
                "❌ SQLite WAL mode error:",
                err.message
            );

        } else {

            console.log(
                "✅ SQLite WAL mode enabled"
            );

        }

    }
);


db.run(
    "PRAGMA synchronous = NORMAL",
    err => {

        if (err) {

            console.error(
                "❌ SQLite synchronous setting error:",
                err.message
            );

        }

    }
);


db.run(
    "PRAGMA busy_timeout = 5000",
    err => {

        if (err) {

            console.error(
                "❌ SQLite busy timeout error:",
                err.message
            );

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

function isBlocked(
a,
b,
cb
) {

db.get(
    `
    SELECT 1
    FROM blocks
    WHERE
        (blocker=? AND blocked=?)
        OR
        (blocker=? AND blocked=?)
    `,
    [
        a,
        b,
        b,
        a
    ],
    (e, row) => {

        cb(!!row);

    }
);

}

// ============================================================
// HWID
// ============================================================

function banHWID(
hwid,
reason
) {

if (!hwid) {
    return;
}


db.run(
    `
    INSERT OR IGNORE INTO hwid_bans
    VALUES(?,?,?)
    `,
    [
        hwid,
        reason,
        Date.now()
    ],
    err => {

        if (err) {

            console.error(
                "❌ Failed to ban HWID:",
                err.message
            );

        }

    }
);

}

function isHWIDBanned(
hwid,
cb
) {

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

        cb(
            row
                ? row.reason
                : null
        );

    }
);

}

// ============================================================
// CHEAT DETECTION
// ============================================================

function isImpossible(
oldS,
newS
) {

if (
    !oldS ||
    !oldS.kills
) {

    return false;

}


if (
    (newS.kills || 0) -
    (oldS.kills || 0) >
    50
) {

    return true;

}


if (
    (newS.bossKills || 0) -
    (oldS.bossKills || 0) >
    3
) {

    return true;

}


if (
    (newS.xp || 0) -
    (oldS.xp || 0) >
    10000
) {

    return true;

}


if (
    (newS.timeSurvived || 0) -
    (oldS.timeSurvived || 0) >
    3600
) {

    return true;

}


return false;

}

function flag(
username,
reason
) {

console.log(
    "🚨 CHEAT:",
    username,
    reason
);


db.get(
    `
    SELECT device
    FROM users
    WHERE username=?
    `,
    [username],
    (e, row) => {

        if (
            row?.device
        ) {

            if (
                reason ===
                    "IMPOSSIBLE_PROGRESS" ||
                reason ===
                    "BAD_SIGNATURE"
            ) {

                banHWID(
                    row.device,
                    "Cheating"
                );

            }

        }

    }
);


db.run(
    `
    UPDATE users
    SET cheat_flags = cheat_flags + 1
    WHERE username=?
    `,
    [username]
);

}

// ============================================================
// TIER
// ============================================================

function computeTier(
stats
) {

if (
    (stats.bossKills || 0) >= 25
) {

    return 7;

}


if (
    (stats.bossKills || 0) >= 18
) {

    return 6;

}


if (
    (stats.bossKills || 0) >= 12
) {

    return 5;

}


if (
    (stats.bossKills || 0) >= 8
) {

    return 4;

}


if (
    (stats.bossKills || 0) >= 5
) {

    return 3;

}


if (
    (stats.bossKills || 0) >= 3
) {

    return 2;

}


return 1;

}

// ============================================================
// HTTP SERVER
// ============================================================

const server =
http.createServer(
(req, res) => {

        // Railway health endpoint.

        if (
            req.url === "/health"
        ) {

            res.writeHead(
                200,
                {
                    "Content-Type":
                        "text/plain"
                }
            );

            res.end("OK");

            return;

        }


        // Normal response.

        res.writeHead(
            200,
            {
                "Content-Type":
                    "text/plain"
            }
        );

        res.end(
            "Auth server online"
        );

    }
);

// ============================================================
// WEBSOCKET SERVER
// ============================================================

const wss =
new WebSocketServer({
server
});

wss.on(
"connection",
(ws) => {

    console.log(
        "🔌 WebSocket client connected"
    );


    // ====================================================
    // MESSAGE
    // ====================================================

    ws.on(
        "message",
        (msg) => {

            let data;


            try {

                data =
                    JSON.parse(
                        msg.toString()
                    );

            } catch {

                console.log(
                    "⚠️ Invalid JSON received"
                );

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


            if (
                !type ||
                !username
            ) {

                return;

            }


            // ====================================================
            // SECURITY
            // ====================================================

            // REGISTER and LOGIN are the only
            // messages that do not require
            // an existing secret.

            if (
                type !== "REGISTER" &&
                type !== "LOGIN"
            ) {

                if (!secret) {

                    return;

                }


                if (
                    sign(
                        username,
                        secret
                    ) !== sig
                ) {

                    flag(
                        username,
                        "BAD_SIGNATURE"
                    );

                    return;

                }

            }


            // ====================================================
           
            // Server-authoritative admin status for this authenticated socket.
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

            // PRESENCE
            // ====================================================

            if (
                type === "PRESENCE_SET"
            ) {

                ws.presence =
                    data.state ||
                    "online";

                ws.username =
                    username;


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

            if (
                type === "CHAT"
            ) {

                const {
                    message,
                    channel,
                    target,
                    msgId
                } = data;


                if (
                    !message ||
                    message.length > 200
                ) {

                    return;

                }


                // Server-side spam throttle.

                if (
                    !ws.lastChat
                ) {

                    ws.lastChat = 0;

                }


                if (
                    Date.now() -
                        ws.lastChat <
                    200
                ) {

                    return;

                }


                ws.lastChat =
                    Date.now();


                const payload =
                    JSON.stringify({
                        type:
                            "CHAT_RESP",
                        username,
                        message,
                        channel,
                        target,
                        msgId,
                        serverTime:
                            Date.now()
                    });


                // IMPORTANT:
                // Keep chat broadcast behavior unchanged.
                // Every connected client receives the message.
                // The Unity UI handles final visibility filtering.

                wss.clients.forEach(
                    client => {

                        if (
                            client.readyState === 1
                        ) {

                            client.send(payload);

                        }

                    }
                );


                return;

            }


            // ====================================================
            // REGISTER
            // ====================================================

            if (
                type === "REGISTER"
            ) {

                if (
                    !password_hash
                ) {

                    ws.send(
                        JSON.stringify({

                            type:
                                "REGISTER_RESP",

                            success:
                                false,

                            message:
                                "Invalid password."

                        })
                    );

                    return;

                }


                const s =
                    makeSecret();


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

                        ws.send(
                            JSON.stringify({

                                type:
                                    "REGISTER_RESP",

                                success:
                                    !err,

                                secret:
                                    s,

                                message:
                                    err
                                        ? "Registration failed."
                                        : "Registration successful."

                            })
                        );


                        if (!err) {

                            // Fill any remaining random admin slots.
                            ensureRandomAdmins();

                        }

                    }
                );


                return;

            }


            // ====================================================
            // LOGIN
            // ====================================================

            if (
                type === "LOGIN"
            ) {

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

                        if (
                            !row ||
                            row.password_hash !==
                                password_hash
                        ) {

                            ws.send(
                                JSON.stringify({

                                    type:
                                        "LOGIN_RESP",

                                    success:
                                        false

                                })
                            );

                            return;

                        }


                        // ====================================================
                        // ACCOUNT BAN CHECK
                        // ====================================================

                        db.get(
                            `
                            SELECT reason
                            FROM account_bans
                            WHERE username=?
                            `,
                            [username],
                            (banErr, banRow) => {

                                if (banRow) {

                                    ws.send(
                                        JSON.stringify({

                                            type:
                                                "LOGIN_RESP",

                                            success:
                                                false,

                                            message:
                                                "Account banned: " +
                                                (banRow.reason || "No reason provided.")

                                        })
                                    );

                                    return;

                                }


                                // ====================================================
                                // HWID BAN CHECK
                                // ====================================================

                                isHWIDBanned(
                                    device,
                                    hwidReason => {

                                        if (hwidReason) {

                                            ws.send(
                                                JSON.stringify({

                                                    type:
                                                        "LOGIN_RESP",

                                                    success:
                                                        false,

                                                    message:
                                                        "Device banned: " +
                                                        hwidReason

                                                })
                                            );

                                            return;

                                        }


                                        // ====================================================
                                        // CHEAT FLAG BAN
                                        // ====================================================

                                        if (
                                            row.cheat_flags >= 3
                                        ) {

                                            ws.send(
                                                JSON.stringify({

                                                    type:
                                                        "LOGIN_RESP",

                                                    success:
                                                        false,

                                                    message:
                                                        "Account banned"

                                                })
                                            );

                                            return;

                                        }


                                        // ====================================================
                                        // REPLACE OLD SESSION
                                        // ====================================================

                                        if (
                                            onlineUsers.has(username)
                                        ) {

                                            try {

                                                onlineUsers
                                                    .get(username)
                                                    .close();

                                            } catch {}

                                        }


                                        onlineUsers.set(
                                            username,
                                            ws
                                        );


                                        ws.username =
                                            username;


                                        // ====================================================
                                        // ADMIN STATUS
                                        // ====================================================

                                        getAdmin(
                                            username,
                                            isAdmin => {

                                                ws.isAdmin =
                                                    isAdmin;

                                                ws.adminStatus =
                                                    isAdmin;


                                                ws.send(
                                                    JSON.stringify({

                                                        type:
                                                            "LOGIN_RESP",

                                                        success:
                                                            true,

                                                        secret:
                                                            row.secret,

                                                        admin:
                                                            isAdmin

                                                    })
                                                );


                                                ws.send(
                                                    JSON.stringify({

                                                        type:
                                                            "ADMIN_STATUS",

                                                        admin:
                                                            isAdmin

                                                    })
                                                );


                                                // ====================================================
                                                // PRESENCE
                                                // ====================================================

                                                broadcastPresence(
                                                    username,
                                                    true,
                                                    "online"
                                                );


                                                broadcastToFriends(
                                                    username,
                                                    true
                                                );


                                                sendInitialPresence(
                                                    username
                                                );

                                            }
                                        );

                                    }
                                );

                            }
                        );

                    }
                );


                return;

            }
// ============================================================
// CONTINUATION OF SERVER MESSAGE HANDLER
// ============================================================

// The following section continues the authenticated
// WebSocket message handling.

// ============================================================
// HWID BAN HELPERS
// ============================================================

function banHWID(
    hwid,
    reason
) {

    if (!hwid) {
        return;
    }

    db.run(
        `
        INSERT OR IGNORE INTO hwid_bans
        VALUES(?,?,?)
        `,
        [
            hwid,
            reason,
            Date.now()
        ],
        err => {

            if (err) {

                console.error(
                    "❌ Failed to ban HWID:",
                    err.message
                );

            }

        }
    );

}

function isHWIDBanned(
    hwid,
    cb
) {

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

            cb(
                row
                    ? row.reason
                    : null
            );

        }
    );

}

// ============================================================
// CHEAT DETECTION
// ============================================================

function isImpossible(
    oldS,
    newS
) {

    if (
        !oldS ||
        !oldS.kills
    ) {

        return false;

    }

    if (
        (newS.kills || 0) -
        (oldS.kills || 0) >
        50
    ) {

        return true;

    }

    if (
        (newS.bossKills || 0) -
        (oldS.bossKills || 0) >
        3
    ) {

        return true;

    }

    if (
        (newS.xp || 0) -
        (oldS.xp || 0) >
        10000
    ) {

        return true;

    }

    if (
        (newS.timeSurvived || 0) -
        (oldS.timeSurvived || 0) >
        3600
    ) {

        return true;

    }

    return false;

}

function flag(
    username,
    reason
) {

    console.log(
        "🚨 CHEAT:",
        username,
        reason
    );

    db.get(
        `
        SELECT device
        FROM users
        WHERE username=?
        `,
        [username],
        (e, row) => {

            if (
                row?.device
            ) {

                if (
                    reason ===
                        "IMPOSSIBLE_PROGRESS" ||
                    reason ===
                        "BAD_SIGNATURE"
                ) {

                    banHWID(
                        row.device,
                        "Cheating"
                    );

                }

            }

        }
    );

    db.run(
        `
        UPDATE users
        SET cheat_flags = cheat_flags + 1
        WHERE username=?
        `,
        [username]
    );

}

// ============================================================
// TIER
// ============================================================

function computeTier(
    stats
) {

    if (
        (stats.bossKills || 0) >= 25
    ) {

        return 7;

    }

    if (
        (stats.bossKills || 0) >= 18
    ) {

        return 6;

    }

    if (
        (stats.bossKills || 0) >= 12
    ) {

        return 5;

    }

    if (
        (stats.bossKills || 0) >= 8
    ) {

        return 4;

    }

    if (
        (stats.bossKills || 0) >= 5
    ) {

        return 3;

    }

    if (
        (stats.bossKills || 0) >= 3
    ) {

        return 2;

    }

    return 1;

}

// ============================================================
// HTTP SERVER
// ============================================================

const server =
    http.createServer(
        (req, res) => {

            // Railway health endpoint.

            if (
                req.url === "/health"
            ) {

                res.writeHead(
                    200,
                    {
                        "Content-Type":
                            "text/plain"
                    }
                );

                res.end("OK");

                return;

            }

            // Normal response.

            res.writeHead(
                200,
                {
                    "Content-Type":
                        "text/plain"
                }
            );

            res.end(
                "Auth server online"
            );

        }
    );

// ============================================================
// WEBSOCKET SERVER
// ============================================================

const wss =
    new WebSocketServer({
        server
    });

wss.on(
    "connection",
    (ws) => {

        console.log(
            "🔌 WebSocket client connected"
        );

        // ====================================================
        // MESSAGE
        // ====================================================

        ws.on(
            "message",
            (msg) => {

                let data;

                try {

                    data =
                        JSON.parse(
                            msg.toString()
                        );

                } catch {

                    console.log(
                        "⚠️ Invalid JSON received"
                    );

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

                if (
                    !type ||
                    !username
                ) {

                    return;

                }

                // ====================================================
                // SECURITY
                // ====================================================

                // REGISTER and LOGIN are the only
                // messages that do not require
                // an existing secret.

                if (
                    type !== "REGISTER" &&
                    type !== "LOGIN"
                ) {

                    if (!secret) {

                        return;

                    }

                    if (
                        sign(
                            username,
                            secret
                        ) !== sig
                    ) {

                        flag(
                            username,
                            "BAD_SIGNATURE"
                        );

                        return;

                    }

                }

                // ====================================================
                // SERVER-AUTHORITATIVE ADMIN STATUS
                // ====================================================

                getAdmin(
                    username,
                    (admin) => {

                        ws.username =
                            username;

                        ws.isAdmin =
                            admin;

                        if (
                            ws.adminStatus !==
                            admin
                        ) {

                            ws.adminStatus =
                                admin;

                            ws.send(
                                JSON.stringify({

                                    type:
                                        "ADMIN_STATUS",

                                    admin:
                                        admin

                                })
                            );

                        }

                    }
                );

                // ====================================================
                // PRESENCE
                // ====================================================

                if (
                    type === "PRESENCE_SET"
                ) {

                    ws.presence =
                        data.state ||
                        "online";

                    ws.username =
                        username;

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

                if (
                    type === "CHAT"
                ) {

                    const {
                        message,
                        channel,
                        target,
                        msgId
                    } = data;

                    if (
                        !message ||
                        message.length > 200
                    ) {

                        return;

                    }

                    // Server-side spam throttle.

                    if (
                        !ws.lastChat
                    ) {

                        ws.lastChat = 0;

                    }

                    if (
                        Date.now() -
                        ws.lastChat <
                        200
                    ) {

                        return;

                    }

                    ws.lastChat =
                        Date.now();

                    const payload =
                        JSON.stringify({

                            type:
                                "CHAT_RESP",

                            username,

                            message,

                            channel,

                            target,

                            msgId,

                            serverTime:
                                Date.now()

                        });

                    // IMPORTANT:
                    //
                    // Chat is intentionally broadcast
                    // to every connected client.
                    //
                    // SimpleChatUI performs the final
                    // whisper visibility filtering.
                    //
                    // DO NOT change this to
                    // target-only routing.

                    wss.clients.forEach(
                        client => {

                            if (
                                client.readyState === 1
                            ) {

                                client.send(
                                    payload
                                );

                            }

                        }
                    );

                    return;

                }

                // ====================================================
                // REGISTER
                // ====================================================

                if (
                    type === "REGISTER"
                ) {

                    const s =
                        makeSecret();

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

                                console.error(
                                    "❌ Registration failed:",
                                    err.message
                                );

                                ws.send(
                                    JSON.stringify({

                                        type:
                                            "REGISTER_RESP",

                                        success:
                                            false

                                    })
                                );

                            } else {

                                console.log(
                                    "✅ Registered user:",
                                    username
                                );

                                // If the permanent admin
                                // slots are not full yet,
                                // randomly fill the remaining
                                // slots from the player base.

                                ensureRandomAdmins();

                                ws.send(
                                    JSON.stringify({

                                        type:
                                            "REGISTER_RESP",

                                        success:
                                            true,

                                        secret:
                                            s

                                    })
                                );

                            }

                        }
                    );

                    return;

                }

                // ====================================================
                // LOGIN
                // ====================================================

                if (
                    type === "LOGIN"
                ) {

                    isHWIDBanned(
                        device,
                        (reason) => {

                            if (reason) {

                                ws.send(
                                    JSON.stringify({

                                        type:
                                            "LOGIN_RESP",

                                        success:
                                            false,

                                        message:
                                            "HWID BANNED: " +
                                            reason

                                    })
                                );

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

                                    if (
                                        !row ||
                                        row.password_hash !==
                                            password_hash
                                    ) {

                                        ws.send(
                                            JSON.stringify({

                                                type:
                                                    "LOGIN_RESP",

                                                success:
                                                    false

                                            })
                                        );

                                        return;

                                    }

                                    db.get(
                                        `
                                        SELECT reason
                                        FROM account_bans
                                        WHERE username=?
                                        `,
                                        [username],
                                        (banErr, banRow) => {

                                            if (banRow) {

                                                ws.send(
                                                    JSON.stringify({

                                                        type:
                                                            "LOGIN_RESP",

                                                        success:
                                                            false,

                                                        message:
                                                            "Account banned: " +
                                                            (
                                                                banRow.reason ||
                                                                "Moderator ban"
                                                            )

                                                    })
                                                );

                                                return;

                                            }

                                            if (
                                                row.cheat_flags >=
                                                3
                                            ) {

                                                ws.send(
                                                    JSON.stringify({

                                                        type:
                                                            "LOGIN_RESP",

                                                        success:
                                                            false,

                                                        message:
                                                            "Account banned"

                                                    })
                                                );

                                                return;

                                            }

                                            // First login binds device.

                                            if (
                                                !row.device
                                            ) {

                                                db.run(
                                                    `
                                                    UPDATE users
                                                    SET device=?
                                                    WHERE username=?
                                                    `,
                                                    [
                                                        device,
                                                        username
                                                    ]
                                                );

                                            }

                                            // Different device = lock.

                                            else if (
                                                row.device !==
                                                device
                                            ) {

                                                banHWID(
                                                    device,
                                                    "Account sharing / evasion"
                                                );

                                                ws.send(
                                                    JSON.stringify({

                                                        type:
                                                            "LOGIN_RESP",

                                                        success:
                                                            false,

                                                        message:
                                                            "Account locked"

                                                    })
                                                );

                                                return;

                                            }

                                            // ====================================================
                                            // ADMIN STATUS
                                            // ====================================================

                                            getAdmin(
                                                username,
                                                (admin) => {

                                                    ws.username =
                                                        username;

                                                    ws.isAdmin =
                                                        admin;

                                                    ws.adminStatus =
                                                        admin;

                                                    ws.send(
                                                        JSON.stringify({

                                                            type:
                                                                "LOGIN_RESP",

                                                            success:
                                                                true,

                                                            secret:
                                                                row.secret,

                                                            admin:
                                                                admin

                                                        })
                                                    );

                                                    ws.send(
                                                        JSON.stringify({

                                                            type:
                                                                "ADMIN_STATUS",

                                                            admin:
                                                                admin

                                                        })
                                                    );

                                                    // ====================================================
                                                    // PRESENCE
                                                    // ====================================================

                                                    broadcastPresence(
                                                        username,
                                                        true,
                                                        "online"
                                                    );

                                                    broadcastToFriends(
                                                        username,
                                                        true
                                                    );

                                                    sendInitialPresence(
                                                        username
                                                    );

                                                }
                                            );

                                        }
                                    );

                                }
                            );

                        }
                    );

                    return;

                }

                // ====================================================
                // FRIEND REQUEST
                // ====================================================

                if (
                    type === "FRIEND_REQUEST"
                ) {

                    const targetUser =
                        data.target ||
                        data.to_user;

                    if (
                        !targetUser ||
                        targetUser === username
                    ) {

                        return;

                    }

                    db.get(
                        `
                        SELECT username
                        FROM users
                        WHERE username=?
                        `,
                        [targetUser],
                        (e, row) => {

                            if (
                                e ||
                                !row
                            ) {

                                ws.send(
                                    JSON.stringify({

                                        type:
                                            "ERROR",

                                        message:
                                            "Player not found."

                                    })
                                );

                                return;

                            }

                            isBlocked(
                                username,
                                targetUser,
                                blocked => {

                                    if (blocked) {

                                        ws.send(
                                            JSON.stringify({

                                                type:
                                                    "ERROR",

                                                message:
                                                    "Player is blocked."

                                            })
                                        );

                                        return;

                                    }

                                    const [
                                        a,
                                        b
                                    ] =
                                        normalizePair(
                                            username,
                                            targetUser
                                        );

                                    db.get(
                                        `
                                        SELECT 1
                                        FROM friends
                                        WHERE
                                            user1=?
                                            AND user2=?
                                        `,
                                        [
                                            a,
                                            b
                                        ],
                                        (friendErr, existingFriend) => {

                                            if (
                                                existingFriend
                                            ) {

                                                ws.send(
                                                    JSON.stringify({

                                                        type:
                                                            "ERROR",

                                                        message:
                                                            "Already friends."

                                                    })
                                                );

                                                return;

                                            }

                                            db.run(
                                                `
                                                INSERT OR IGNORE INTO friend_requests(
                                                    from_user,
                                                    to_user,
                                                    created_at
                                                )
                                                VALUES(?,?,?)
                                                `,
                                                [
                                                    username,
                                                    targetUser,
                                                    Date.now()
                                                ],
                                                requestErr => {

                                                    if (
                                                        requestErr
                                                    ) {

                                                        ws.send(
                                                            JSON.stringify({

                                                                type:
                                                                    "ERROR",

                                                                message:
                                                                    "Friend request failed."

                                                            })
                                                        );

                                                        return;

                                                    }

                                                    ws.send(
                                                        JSON.stringify({

                                                            type:
                                                                "FRIEND_UPDATE",

                                                            action:
                                                                "REQUEST_SENT",

                                                            user:
                                                                targetUser

                                                        })
                                                    );

                                                    const targetWs =
                                                        onlineUsers.get(
                                                            targetUser
                                                        );

                                                    if (
                                                        targetWs &&
                                                        targetWs.readyState ===
                                                        1
                                                    ) {

                                                        targetWs.send(
                                                            JSON.stringify({

                                                                type:
                                                                    "FRIEND_UPDATE",

                                                                action:
                                                                    "REQUEST_RECEIVED",

                                                                user:
                                                                    username

                                                            })
                                                        );

                                                    }

                                                }
                                            );

                                        }
                                    );

                                }
                            );

                        }
                    );

                    return;

                }

                // ====================================================
                // FRIEND REQUEST WITHDRAW
                // ====================================================

                if (
                    type === "FRIEND_WITHDRAW"
                ) {

                    const targetUser =
                        data.target ||
                        data.to_user;

                    if (!targetUser) {
                        return;
                    }

                    db.run(
                        `
                        DELETE FROM friend_requests
                        WHERE
                            from_user=?
                            AND to_user=?
                        `,
                        [
                            username,
                            targetUser
                        ],
                        () => {

                            ws.send(
                                JSON.stringify({

                                    type:
                                        "FRIEND_UPDATE",

                                    action:
                                        "REQUEST_WITHDRAWN",

                                    user:
                                        targetUser

                                })
                            );

                            const targetWs =
                                onlineUsers.get(
                                    targetUser
                                );

                            if (
                                targetWs &&
                                targetWs.readyState === 1
                            ) {

                                targetWs.send(
                                    JSON.stringify({

                                        type:
                                            "FRIEND_UPDATE",

                                        action:
                                            "REQUEST_WITHDRAWN",

                                        user:
                                            username

                                    })
                                );

                            }

                        }
                    );

                    return;

                }

                // ====================================================
                // FRIEND ACCEPT
                // ====================================================

                if (
                    type === "FRIEND_ACCEPT"
                ) {

                    const fromUser =
                        data.from_user ||
                        data.target;

                    if (!fromUser) {
                        return;
                    }

                    db.get(
                        `
                        SELECT 1
                        FROM friend_requests
                        WHERE
                            from_user=?
                            AND to_user=?
                        `,
                        [
                            fromUser,
                            username
                        ],
                        (e, request) => {

                            if (!request) {
                                return;
                            }

                            const [
                                a,
                                b
                            ] =
                                normalizePair(
                                    username,
                                    fromUser
                                );

                            db.run(
                                `
                                INSERT OR IGNORE INTO friends(
                                    user1,
                                    user2,
                                    created_at
                                )
                                VALUES(?,?,?)
                                `,
                                [
                                    a,
                                    b,
                                    Date.now()
                                ],
                                () => {

                                    db.run(
                                        `
                                        DELETE FROM friend_requests
                                        WHERE
                                            from_user=?
                                            AND to_user=?
                                        `,
                                        [
                                            fromUser,
                                            username
                                        ],
                                        () => {

                                            ws.send(
                                                JSON.stringify({

                                                    type:
                                                        "FRIEND_UPDATE",

                                                    action:
                                                        "FRIEND_ADDED",

                                                    user:
                                                        fromUser

                                                })
                                            );

                                            const targetWs =
                                                onlineUsers.get(
                                                    fromUser
                                                );

                                            if (
                                                targetWs &&
                                                targetWs.readyState ===
                                                1
                                            ) {

                                                targetWs.send(
                                                    JSON.stringify({

                                                        type:
                                                            "FRIEND_UPDATE",

                                                        action:
                                                            "FRIEND_ADDED",

                                                        user:
                                                            username

                                                    })
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

                if (
                    type === "FRIEND_REJECT"
                ) {

                    const fromUser =
                        data.from_user ||
                        data.target;

                    if (!fromUser) {
                        return;
                    }

                    db.run(
                        `
                        DELETE FROM friend_requests
                        WHERE
                            from_user=?
                            AND to_user=?
                        `,
                        [
                            fromUser,
                            username
                        ],
                        () => {

                            ws.send(
                                JSON.stringify({

                                    type:
                                        "FRIEND_UPDATE",

                                    action:
                                        "REQUEST_REJECTED",

                                    user:
                                        fromUser

                                })
                            );

                        }
                    );

                    return;

                }

                // ====================================================
                // FRIEND DELETE
                // ====================================================

                if (
                    type === "FRIEND_DELETE"
                ) {

                    const friend =
                        data.target ||
                        data.user ||
                        data.friend;

                    if (!friend) {
                        return;
                    }

                    const [
                        a,
                        b
                    ] =
                        normalizePair(
                            username,
                            friend
                        );

                    db.run(
                        `
                        DELETE FROM friends
                        WHERE
                            user1=?
                            AND user2=?
                        `,
                        [
                            a,
                            b
                        ],
                        () => {

                            ws.send(
                                JSON.stringify({

                                    type:
                                        "FRIEND_UPDATE",

                                    action:
                                        "FRIEND_DELETED",

                                    user:
                                        friend

                                })
                            );

                            const targetWs =
                                onlineUsers.get(
                                    friend
                                );

                            if (
                                targetWs &&
                                targetWs.readyState === 1
                            ) {

                                targetWs.send(
                                    JSON.stringify({

                                        type:
                                            "FRIEND_UPDATE",

                                        action:
                                            "FRIEND_DELETED",

                                        user:
                                            username

                                    })
                                );

                            }

                        }
                    );

                    return;

                }

                // ====================================================
                // BLOCK ADD
                // ====================================================

                if (
                    type === "BLOCK_ADD"
                ) {

                    const blocked =
                        data.target ||
                        data.blocked ||
                        data.user;

                    if (
                        !blocked ||
                        blocked === username
                    ) {

                        return;

                    }

                    db.run(
                        `
                        INSERT OR IGNORE INTO blocks(
                            blocker,
                            blocked,
                            created_at
                        )
                        VALUES(?,?,?)
                        `,
                        [
                            username,
                            blocked,
                            Date.now()
                        ],
                        () => {

                            ws.send(
                                JSON.stringify({

                                    type:
                                        "FRIEND_UPDATE",

                                    action:
                                        "BLOCK_ADDED",

                                    user:
                                        blocked

                                })
                            );

                        }
                    );

                    return;

                }

                // ====================================================
                // BLOCK REMOVE
                // ====================================================

                if (
                    type === "BLOCK_REMOVE"
                ) {

                    const blocked =
                        data.target ||
                        data.blocked ||
                        data.user;

                    if (!blocked) {
                        return;
                    }

                    db.run(
                        `
                        DELETE FROM blocks
                        WHERE
                            blocker=?
                            AND blocked=?
                        `,
                        [
                            username,
                            blocked
                        ],
                        () => {

                            ws.send(
                                JSON.stringify({

                                    type:
                                        "FRIEND_UPDATE",

                                    action:
                                        "BLOCK_REMOVED",

                                    user:
                                        blocked

                                })
                            );

                        }
                    );

                    return;

                }
                                            type:
                                                "LOGIN_RESP",

                                            success:
                                                true,

                                            secret:
                                                row.secret,

                                            flags:
                                                row.cheat_flags,

                                            admin: admin

                                        })
                                    );
                                   
                                    ws.send(
                                        JSON.stringify({
                                            type: "ADMIN_STATUS",
                                            admin: admin
                                        })
                                    );
                                });

                            }

                        );

                    }
                );

            }

            return;

        }


        // ====================================================
        // ====================================================
        // PLAYER REPORT
        // ====================================================

        if (type === "REPORT_PLAYER") {

            const target = String(data.target || "").trim();
            const reason = String(data.reason || "").trim().slice(0, 500);

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
                        `INSERT INTO reports(reporter,target,reason,created_at,status) VALUES(?,?,?,?,?)`,
                        [username, target, reason, Date.now(), "open"],
                        err => {
                            ws.send(JSON.stringify({
                                type: "REPORT_PLAYER_RESP",
                                success: !err,
                                message: err ? "Report failed." : "Report submitted."
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
                const reason = String(data.reason || "Moderator ban").trim().slice(0, 300) || "Moderator ban";

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
                            message: err ? "Unban failed." : "Account unbanned."
                        }));

                    }
                );

            });

            return;
        }

        // ====================================================
        // FRIEND REQUEST
        // ====================================================

        if (
            type === "FRIEND_REQUEST"
        ) {

            const target =
                data.target;

            if (
                !target ||
                username === target
            ) {

                return;

            }

            isBlocked(
                username,
                target,
                (blocked) => {

                    if (blocked) {

                        return;

                    }

                    const [
                        u1,
                        u2
                    ] =
                        normalizePair(
                            username,
                            target
                        );

                    db.get(
                        `
                        SELECT 1
                        FROM friends
                        WHERE user1=?
                        AND user2=?
                        `,
                        [
                            u1,
                            u2
                        ],
                        (e, row) => {

                            if (row) {

                                return;

                            }

                            db.run(
                                `
                                INSERT OR IGNORE INTO friend_requests
                                VALUES(?,?,?)
                                `,
                                [
                                    username,
                                    target,
                                    Date.now()
                                ]
                            );

                        }
                    );

                }
            );

            return;

        }


        // ====================================================
        // FRIEND WITHDRAW
        // ====================================================

        if (
            type === "FRIEND_WITHDRAW"
        ) {

            db.run(
                `
                DELETE FROM friend_requests
                WHERE from_user=?
                AND to_user=?
                `,
                [
                    username,
                    data.target
                ]
            );

            return;

        }
                    ]
                );


                return;

            }


            // ====================================================
            // FRIEND ACCEPT
            // ====================================================

            if (
                type === "FRIEND_ACCEPT"
            ) {

                const target =
                    data.target;


                if (
                    !target ||
                    username === target
                ) {

                    return;

                }


                const [
                    u1,
                    u2
                ] =
                    normalizePair(
                        username,
                        target
                    );


                db.get(
                    `
                    SELECT 1
                    FROM friend_requests
                    WHERE from_user=?
                    AND to_user=?
                    `,
                    [
                        target,
                        username
                    ],
                    (e, row) => {

                        if (!row) {

                            return;

                        }


                        db.serialize(
                            () => {

                                db.run(
                                    `
                                    INSERT OR IGNORE INTO friends
                                    VALUES(?,?,?)
                                    `,
                                    [
                                        u1,
                                        u2,
                                        Date.now()
                                    ]
                                );


                                db.run(
                                    `
                                    DELETE FROM friend_requests
                                    WHERE from_user=?
                                    AND to_user=?
                                    `,
                                    [
                                        target,
                                        username
                                    ]
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

            if (
                type === "FRIEND_REJECT"
            ) {

                db.run(
                    `
                    DELETE FROM friend_requests
                    WHERE from_user=?
                    AND to_user=?
                    `,
                    [
                        data.target,
                        username
                    ]
                );


                return;

            }


            // ====================================================
            // FRIEND DELETE
            // ====================================================

            if (
                type === "FRIEND_DELETE"
            ) {

                const [
                    u1,
                    u2
                ] =
                    normalizePair(
                        username,
                        data.target
                    );


                db.run(
                    `
                    DELETE FROM friends
                    WHERE user1=?
                    AND user2=?
                    `,
                    [
                        u1,
                        u2
                    ]
                );


                return;

            }


            // ====================================================
            // BLOCK ADD
            // ====================================================

            if (
                type === "BLOCK_ADD"
            ) {

                const target =
                    data.target;


                if (
                    !target ||
                    username === target
                ) {

                    return;

                }


                db.serialize(
                    () => {

                        db.run(
                            `
                            INSERT OR IGNORE INTO blocks
                            VALUES(?,?,?)
                            `,
                            [
                                username,
                                target,
                                Date.now()
                            ]
                        );


                        const [
                            u1,
                            u2
                        ] =
                            normalizePair(
                                username,
                                target
                            );


                        db.run(
                            `
                            DELETE FROM friends
                            WHERE user1=?
                            AND user2=?
                            `,
                            [
                                u1,
                                u2
                            ]
                        );


                        db.run(
                            `
                            DELETE FROM friend_requests
                            WHERE
                                (from_user=? AND to_user=?)
                            OR
                                (from_user=? AND to_user=?)
                            `,
                            [
                                username,
                                target,
                                target,
                                username
                            ]
                        );

                    }
                );


                return;

            }


            // ====================================================
            // BLOCK REMOVE
            // ====================================================

            if (
                type === "BLOCK_REMOVE"
            ) {

                db.run(
                    `
                    DELETE FROM blocks
                    WHERE blocker=?
                    AND blocked=?
                    `,
                    [
                        username,
                        data.target
                    ]
                );


                return;

            }


            // ====================================================
            // LOAD FRIENDS
            // ====================================================

            if (
                type === "FRIENDS_LOAD"
            ) {

                db.all(
                    `
                    SELECT *
                    FROM friends
                    WHERE user1=?
                    OR user2=?
                    `,
                    [
                        username,
                        username
                    ],
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

                                        ws.send(
                                            JSON.stringify({

                                                type:
                                                    "FRIENDS_LOAD_RESP",

                                                friends:
                                                    friends ||
                                                    [],

                                                requests:
                                                    requests ||
                                                    [],

                                                blocks:
                                                    blocks ||
                                                    []

                                            })
                                        );

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

            if (
                type === "STATS_SAVE"
            ) {

                db.get(
                    `
                    SELECT
                        secret,
                        last_stats_hash
                    FROM users
                    WHERE username=?
                    `,
                    [username],
                    (e, user) => {

                        if (!user) {

                            return;

                        }


                        if (
                            sign(
                                json,
                                user.secret
                            ) !== sig
                        ) {

                            flag(
                                username,
                                "BAD_SIGNATURE"
                            );

                            return;

                        }


                        const newHash =
                            sha(json);


                        if (
                            newHash ===
                            user.last_stats_hash
                        ) {

                            return;

                        }


                        db.run(
                            `
                            UPDATE users
                            SET last_stats_hash=?
                            WHERE username=?
                            `,
                            [
                                newHash,
                                username
                            ]
                        );


                        db.run(
                            `
                            INSERT INTO player_stats
                            (username,json)
                            VALUES(?,?)
                            ON CONFLICT(username)
                            DO UPDATE SET json=excluded.json
                            `,
                            [
                                username,
                                json
                            ]
                        );

                    }
                );


                return;

            }
                        ) {
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
                                    oldS =
                                        row
                                            ? JSON.parse(
                                                row.json
                                            )
                                            : {};

                                    newS =
                                        JSON.parse(
                                            json
                                        );

                                } catch {

                                    flag(
                                        username,
                                        "BAD_STATS_JSON"
                                    );

                                    return;
                                }


                                if (
                                    isImpossible(
                                        oldS,
                                        newS
                                    )
                                ) {

                                    flag(
                                        username,
                                        "IMPOSSIBLE_PROGRESS"
                                    );

                                    return;
                                }


                                db.run(
                                    `
                                    INSERT INTO player_stats(
                                        username,
                                        json
                                    )
                                    VALUES(?,?)
                                    ON CONFLICT(username)
                                    DO UPDATE SET
                                        json=excluded.json
                                    `,
                                    [
                                        username,
                                        json
                                    ]
                                );


                                db.run(
                                    `
                                    UPDATE users
                                    SET last_stats_hash=?
                                    WHERE username=?
                                    `,
                                    [
                                        newHash,
                                        username
                                    ]
                                );

                                // Persistent backup
                                // on Railway Volume.

                                try {

                                    fs.writeFileSync(
                                        path.join(
                                            BACKUP_DIR,
                                            `${username}.json`
                                        ),
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

            if (
                type === "STATS_LOAD"
            ) {

                db.get(
                    `
                    SELECT secret
                    FROM users
                    WHERE username=?
                    `,
                    [username],
                    (e, u) => {

                        if (
                            !u ||
                            u.secret !== secret
                        ) {

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

                                ws.send(
                                    JSON.stringify({

                                        type:
                                            "STATS_LOAD_RESP",
                                        json:
                                            row
                                                ? row.json
                                                : "{}"

                                    })
                                );

                            }
                        );

                    }
                );


                return;
            }


            // ====================================================
            // TIER LOAD
            // ====================================================

            if (
                type === "TIER_LOAD"
            ) {

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

                            stats =
                                row
                                    ? JSON.parse(
                                        row.json
                                    )
                                    : {};

                        } catch {

                            stats = {};

                        }


                        const tier =
                            computeTier(
                                stats
                            );


                        const tierSignature =
                            sign(
                                "TIER_" + tier,
                                secret
                            );


                        ws.send(
                            JSON.stringify({

                                type:
                                    "TIER_RESP",

                                tier,

                                sig:
                                    tierSignature

                            })
                        );

                    }
                );


                return;
            }

        }
    );


    // ========================================================
    // DISCONNECT
    // ========================================================

    ws.on(
        "close",
        () => {

            console.log(
                "🔌 WebSocket client disconnected"
            );


            if (
                ws.username
            ) {

                broadcastPresence(
                    ws.username,
                    false,
                    "offline"
                );

            }

        }
    );

}
);

// ============================================================
// WEBSOCKET ERROR HANDLING
// ============================================================

wss.on(
"error",
err => {

    console.error(
        "❌ WebSocket server error:",
        err
    );

}
);

// ============================================================
// HTTP SERVER ERROR HANDLING
// ============================================================

server.on(
"error",
err => {

    console.error(
        "❌ HTTP server error:",
        err
    );

}
);

// ============================================================
// START SERVER
// ============================================================

const PORT =
process.env.PORT || 3000;

server.listen(
PORT,
"0.0.0.0",
() => {

    console.log(
        "=========================================="
    );

    console.log(
        "🚀 Auth server running on port",
        PORT
    );

    console.log(
        "🌐 Listening on 0.0.0.0"
    );

    console.log(
        "📁 SQLite database:",
        DB_PATH
    );

    console.log("👑 Permanent random admin slots:", RANDOM_ADMIN_COUNT);
   
    console.log(
        "📁 Backups:",
        BACKUP_DIR
    );

    console.log(
        "❤️ Health endpoint:",
        "/health"
    );

    console.log(
        "=========================================="
    );

}
);

// ============================================================
// GRACEFUL SHUTDOWN
// ============================================================

let shuttingDown = false;

function shutdown(signal) {

if (shuttingDown) {

    return;

}


shuttingDown = true;

console.log(
    "=========================================="
);

console.log(
    `🛑 ${signal} received.`
);

console.log(
    "🛑 Beginning graceful shutdown..."
);


// Stop accepting new HTTP/WebSocket
// connections.

server.close(
    () => {

        console.log(
            "✅ HTTP/WebSocket server closed."
        );


        // Force SQLite WAL data back
        // into the main database before
        // closing.

        db.run(
            "PRAGMA wal_checkpoint(FULL)",
            err => {

                if (err) {

                    console.error(
                        "⚠️ SQLite WAL checkpoint error:",
                        err.message
                    );

                } else {

                    console.log(
                        "✅ SQLite WAL checkpoint completed."
                    );

                }


                db.close(
                    closeErr => {

                        if (closeErr) {

                            console.error(
                                "❌ SQLite close error:",
                                closeErr
                            );

                            process.exit(1);

                        }


                        console.log(
                            "✅ SQLite database closed safely."
                        );

                        console.log(
                            "🛑 Server shutdown complete."
                        );

                        console.log(
                            "=========================================="
                        );


                        process.exit(0);

                    }
                );

            }
        );

    }
);


// Safety timeout.
//
// If something prevents shutdown from
// completing, do not leave the container
// hanging indefinitely.

setTimeout(
    () => {

        console.error(
            "⚠️ Forced shutdown after timeout."
        );

        process.exit(1);

    },
    10000
).unref();

}

process.on(
"SIGTERM",
() => shutdown("SIGTERM")
);

process.on(
"SIGINT",
() => shutdown("SIGINT")
);
