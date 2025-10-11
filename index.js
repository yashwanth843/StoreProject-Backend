const express = require("express");
const path = require("path");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const { body, validationResult } = require("express-validator");

const app = express();
app.use(cors());
app.use(express.json());

const DB_FILE = path.join(__dirname, "dev.sqlite3");
const JWT_SECRET = process.env.JWT_SECRET || "verysecretkey_for_dev";

let db = null;


const initializeDBAndServer = async () => {
    try {
        db = await open({
            filename: DB_FILE,
            driver: sqlite3.Database,
        });


        await db.run("PRAGMA foreign_keys = ON;");

        // Create tables if they don't exist
        await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        address TEXT,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('ADMIN','USER','OWNER')),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS stores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT,
        address TEXT,
        owner_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE SET NULL
      );

      CREATE TABLE IF NOT EXISTS ratings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        store_id INTEGER NOT NULL,
        rating INTEGER NOT NULL CHECK(rating >= 1 AND rating <= 5),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(store_id) REFERENCES stores(id) ON DELETE CASCADE
      );

      CREATE UNIQUE INDEX IF NOT EXISTS idx_ratings_user_store ON ratings(user_id, store_id);
    `);


        const row = await db.get("SELECT COUNT(*) as c FROM users;");
        if (row && row.c === 0) {
            console.log("Seeding initial data (admin, owner, store)...");
            const adminPassword = "Admin@123";
            const ownerPassword = "Owner@123";
            const adminHash = await bcrypt.hash(adminPassword, 10);
            const ownerHash = await bcrypt.hash(ownerPassword, 10);

            const adminName = "Default System Administrator";
            const ownerName = "Default Store Owner Name Here";

            await db.run(
                `INSERT INTO users (name,email,address,password_hash,role) VALUES (?,?,?,?,?);`,
                [adminName, "admin@example.com", "Head office address", adminHash, "ADMIN"]
            );
            await db.run(
                `INSERT INTO users (name,email,address,password_hash,role) VALUES (?,?,?,?,?);`,
                [ownerName, "owner@example.com", "Owner address", ownerHash, "OWNER"]
            );

            const ownerRow = await db.get(`SELECT id FROM users WHERE email = ?`, ["owner@example.com"]);
            const ownerId = ownerRow.id;

            await db.run(
                `INSERT INTO stores (name,email,address,owner_id) VALUES (?,?,?,?);`,
                ["Sunny Store", "store@example.com", "Market street, City", ownerId]
            );

            console.log("Seed created:");
            console.log(`  Admin -> admin@example.com / ${adminPassword}`);
            console.log(`  Owner -> owner@example.com / ${ownerPassword}`);
        } else {
            console.log("DB found; tables ensured.");
        }


        app.listen(3000, () => {
            console.log(`Server Running at http://localhost:3000/`);
        });
    } catch (e) {
        console.log(`DB Error: ${e.message}`);
        process.exit(1);
    }
};

initializeDBAndServer();



function sendValidationErrors(res, errors) {
    return res.status(400).json({ errors: errors.array() });
}

function authMiddleware(req, res, next) {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: "Missing token" });
    const parts = auth.split(" ");
    if (parts.length !== 2) return res.status(401).json({ error: "Invalid auth header" });
    const token = parts[1];
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        req.auth = payload;
        next();
    } catch (err) {
        return res.status(401).json({ error: "Invalid token" });
    }
}

async function loadUser(req, res, next) {
    if (!req.auth) return res.status(401).json({ error: "No auth" });
    try {
        const user = await db.get("SELECT id,name,email,address,role FROM users WHERE id = ?", [req.auth.id]);
        if (!user) return res.status(401).json({ error: "User not found" });
        req.user = user;
        next();
    } catch (err) {
        next(err);
    }
}

function requireRole(role) {
    return (req, res, next) => {
        if (!req.user || req.user.role !== role) return res.status(403).json({ error: `${role} only` });
        next();
    };
}


const nameRule = body("name")
    .isLength({ min: 3, max: 60 })
    .withMessage("Name must be 3-60 characters");

const addressRule = body("address").isLength({ max: 400 }).optional({ nullable: true, checkFalsy: true });
const passwordRule = body("password")
    .isLength({ min: 8, max: 16 })
    .withMessage("Password must be 8-16 chars")
    .matches(/[A-Z]/)
    .withMessage("Password must include an uppercase letter")
    .matches(/[^A-Za-z0-9]/)
    .withMessage("Password must include a special character");


app.get("/", (req, res) => res.json({ status: "ok", note: "Use /api/* endpoints" }));


app.post(
    "/api/auth/signup",
    [nameRule, body("email").isEmail().withMessage("Invalid email"), addressRule, passwordRule],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return sendValidationErrors(res, errors);

        const { name, email, address, password } = req.body;
        try {
            const existing = await db.get("SELECT id FROM users WHERE email = ?", [email]);
            if (existing) return res.status(400).json({ error: "Email already used" });

            const hash = await bcrypt.hash(password, 10);
            const info = await db.run(
                "INSERT INTO users (name,email,address,password_hash,role) VALUES (?,?,?,?,?);",
                [name, email, address || null, hash, "USER"]
            );

            const token = jwt.sign({ id: info.lastID, role: "USER" }, JWT_SECRET, { expiresIn: "8h" });

            return res.json({
                token,
                user: { id: info.lastID, name, email, role: "USER" }
            });
        } catch (err) {
            console.error("Signup error:", err);
            return res.status(500).json({ error: "Server error" });
        }
    }
);

/* Login */
app.post("/api/auth/login", [body("email").isEmail(), body("password").isString()], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return sendValidationErrors(res, errors);

    const { email, password } = req.body;
    try {
        const row = await db.get("SELECT id, password_hash, role, name, email as em FROM users WHERE email = ?", [email]);
        if (!row) return res.status(400).json({ error: "Invalid credentials" });
        const ok = await bcrypt.compare(password, row.password_hash);
        if (!ok) return res.status(400).json({ error: "Invalid credentials" });
        const token = jwt.sign({ id: row.id, role: row.role }, JWT_SECRET, { expiresIn: "8h" });
        return res.json({ token, user: { id: row.id, name: row.name, email: row.em, role: row.role } });
    } catch (err) {
        console.error("Login error:", err);
        return res.status(500).json({ error: "Server error" });
    }
});



/* Dashboard stats */
app.get("/api/admin/dashboard", authMiddleware, loadUser, requireRole("ADMIN"), async (req, res) => {
    try {
        const u = await db.get("SELECT COUNT(*) as c FROM users");
        const s = await db.get("SELECT COUNT(*) as c FROM stores");
        const r = await db.get("SELECT COUNT(*) as c FROM ratings");
        return res.json({ totalUsers: u.c, totalStores: s.c, totalRatings: r.c });
    } catch (err) {
        console.error("Admin dashboard error:", err);
        return res.status(500).json({ error: "Server error" });
    }
});

/* Create user (admin) */
app.post(
    "/api/admin/users",
    authMiddleware,
    loadUser,
    requireRole("ADMIN"),
    [nameRule, body("email").isEmail(), addressRule, passwordRule, body("role").isIn(["ADMIN", "USER", "OWNER"])],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return sendValidationErrors(res, errors);
        const { name, email, address, password, role } = req.body;
        try {
            const existing = await db.get("SELECT id FROM users WHERE email = ?", [email]);
            if (existing) return res.status(400).json({ error: "Email used" });
            const hash = await bcrypt.hash(password, 10);
            const info = await db.run(
                "INSERT INTO users (name,email,address,password_hash,role) VALUES (?,?,?,?,?);",
                [name, email, address || null, hash, role]
            );
            return res.json({ id: info.lastID });
        } catch (err) {
            console.error("Admin create user error:", err);
            return res.status(500).json({ error: "Server error" });
        }
    }
);

/* Create store (admin) */
app.post(
    "/api/admin/stores",
    authMiddleware,
    loadUser,
    requireRole("ADMIN"),
    [body("name").isLength({ min: 1 }), body("email").isEmail().optional({ nullable: true }), addressRule, body("owner_id").optional().isInt()],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return sendValidationErrors(res, errors);
        const { name, email, address, owner_id } = req.body;
        try {
            if (owner_id) {
                const owner = await db.get("SELECT id, role FROM users WHERE id = ?", [owner_id]);
                if (!owner) return res.status(400).json({ error: "Owner not found" });
                if (owner.role !== "OWNER") return res.status(400).json({ error: "owner_id must be an OWNER" });
            }
            const info = await db.run("INSERT INTO stores (name,email,address,owner_id) VALUES (?,?,?,?)", [name, email || null, address || null, owner_id || null]);
            return res.json({ id: info.lastID });
        } catch (err) {
            console.error("Admin create store error:", err);
            return res.status(500).json({ error: "Server error" });
        }
    }
);

/* List users with filters & sorting (admin) */
app.get("/api/admin/users", authMiddleware, loadUser, requireRole("ADMIN"), async (req, res) => {
    try {
        const qName = req.query.qName ? `%${req.query.qName}%` : null;
        const qEmail = req.query.qEmail ? `%${req.query.qEmail}%` : null;
        const qAddress = req.query.qAddress ? `%${req.query.qAddress}%` : null;
        const role = req.query.role || null;
        const sortBy = ["name", "email", "address", "role"].includes(req.query.sortBy) ? req.query.sortBy : "name";
        const sortDir = req.query.sortDir === "desc" ? "DESC" : "ASC";

        let sql = `SELECT id,name,email,address,role FROM users WHERE 1=1`;
        const params = [];
        if (qName) {
            sql += " AND name LIKE ?";
            params.push(qName);
        }
        if (qEmail) {
            sql += " AND email LIKE ?";
            params.push(qEmail);
        }
        if (qAddress) {
            sql += " AND address LIKE ?";
            params.push(qAddress);
        }
        if (role) {
            sql += " AND role = ?";
            params.push(role);
        }
        sql += ` ORDER BY ${sortBy} ${sortDir} LIMIT 200`;

        const rows = await db.all(sql, params);
        return res.json(rows);
    } catch (err) {
        console.error("Admin list users error:", err);
        return res.status(500).json({ error: "Server error" });
    }
});

/* List stores with avg rating (admin) */
app.get("/api/admin/stores", authMiddleware, loadUser, requireRole("ADMIN"), async (req, res) => {
    try {
        const qName = req.query.qName ? `%${req.query.qName}%` : null;
        const qAddress = req.query.qAddress ? `%${req.query.qAddress}%` : null;

        let sql = `
      SELECT s.id, s.name, s.email, s.address,
        IFNULL(ROUND(AVG(r.rating), 2), 0) as avg_rating
      FROM stores s
      LEFT JOIN ratings r ON s.id = r.store_id
      WHERE 1=1
    `;
        const params = [];
        if (qName) {
            sql += " AND s.name LIKE ?";
            params.push(qName);
        }
        if (qAddress) {
            sql += " AND s.address LIKE ?";
            params.push(qAddress);
        }
        sql += " GROUP BY s.id ORDER BY s.name ASC LIMIT 300";

        const rows = await db.all(sql, params);
        return res.json(rows);
    } catch (err) {
        console.error("Admin list stores error:", err);
        return res.status(500).json({ error: "Server error" });
    }
});



/* List stores (with avg rating and caller's submitted rating attached) */
app.get("/api/stores", authMiddleware, loadUser, async (req, res) => {
    try {
        const qName = req.query.qName ? `%${req.query.qName}%` : null;
        const qAddress = req.query.qAddress ? `%${req.query.qAddress}%` : null;

        let sql = `
      SELECT s.id, s.name, s.email, s.address,
        IFNULL(ROUND(AVG(r.rating), 2), 0) as avg_rating
      FROM stores s
      LEFT JOIN ratings r ON s.id = r.store_id
      WHERE 1=1
    `;
        const params = [];
        if (qName) {
            sql += " AND s.name LIKE ?";
            params.push(qName);
        }
        if (qAddress) {
            sql += " AND s.address LIKE ?";
            params.push(qAddress);
        }
        sql += " GROUP BY s.id ORDER BY s.name ASC";

        const rows = await db.all(sql, params);

        // Attach caller's rating
        const storeIds = rows.map((r) => r.id);
        if (storeIds.length === 0) return res.json([]);
        const placeholders = storeIds.map(() => "?").join(",");
        const myRatings = await db.all(`SELECT store_id, rating FROM ratings WHERE user_id = ? AND store_id IN (${placeholders})`, [req.user.id, ...storeIds]);
        const map = {};
        myRatings.forEach((r) => (map[r.store_id] = r.rating));
        const out = rows.map((r) => ({ ...r, user_rating: map[r.id] ?? null }));
        return res.json(out);
    } catch (err) {
        console.error("List stores error:", err);
        return res.status(500).json({ error: "Server error" });
    }
});

/* Owner: list raters and avg rating for their store(s) */
app.get("/api/stores/owner", authMiddleware, loadUser, async (req, res) => {
    try {
        if (req.user.role !== "OWNER") return res.status(403).json({ error: "Owner only" });

        const stores = await db.all("SELECT * FROM stores WHERE owner_id = ?", [req.user.id]);
        const result = [];
        for (const s of stores) {
            const raters = await db.all(
                `SELECT u.id as user_id, u.name as user_name, r.rating, r.updated_at
         FROM ratings r JOIN users u ON r.user_id = u.id WHERE r.store_id = ? ORDER BY r.updated_at DESC`,
                [s.id]
            );
            const avgRow = await db.get("SELECT AVG(rating) as avg_rating FROM ratings WHERE store_id = ?", [s.id]);
            result.push({ store: s, raters, avg_rating: avgRow ? (avgRow.avg_rating || 0) : 0 });
        }
        return res.json(result);
    } catch (err) {
        console.error("Owner stores error:", err);
        return res.status(500).json({ error: "Server error" });
    }
});



/* Submit or update rating (upsert) */
app.post(
    "/api/ratings",
    authMiddleware,
    loadUser,
    [body("store_id").isInt(), body("rating").isInt({ min: 1, max: 5 })],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return sendValidationErrors(res, errors);
        const user_id = req.user.id;
        const { store_id, rating } = req.body;
        try {
            const store = await db.get("SELECT id FROM stores WHERE id = ?", [store_id]);
            if (!store) return res.status(400).json({ error: "Store not found" });

            const existing = await db.get("SELECT id FROM ratings WHERE user_id = ? AND store_id = ?", [user_id, store_id]);
            if (existing) {
                await db.run("UPDATE ratings SET rating = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", [rating, existing.id]);
                return res.json({ updated: true });
            } else {
                const info = await db.run("INSERT INTO ratings (user_id, store_id, rating) VALUES (?,?,?)", [user_id, store_id, rating]);
                return res.json({ id: info.lastID });
            }
        } catch (err) {
            if (err && err.code === "SQLITE_CONSTRAINT") return res.status(400).json({ error: "Constraint error" });
            console.error("Ratings error:", err);
            return res.status(500).json({ error: "Server error" });
        }
    }
);

/* Delete rating (owner/admin allowed for others? only owner of rating or admin allowed) */
app.delete("/api/ratings/:id", authMiddleware, loadUser, async (req, res) => {
    const id = req.params.id;
    try {
        const row = await db.get("SELECT * FROM ratings WHERE id = ?", [id]);
        if (!row) return res.status(404).json({ error: "Not found" });
        if (row.user_id !== req.user.id && req.user.role !== "ADMIN") return res.status(403).json({ error: "Not allowed" });
        await db.run("DELETE FROM ratings WHERE id = ?", [id]);
        return res.json({ deleted: true });
    } catch (err) {
        console.error("Delete rating error:", err);
        return res.status(500).json({ error: "Server error" });
    }
});



/* Change password for logged-in user */
app.post(
    "/api/user/change-password",
    authMiddleware,
    loadUser,
    [body("oldPassword").isString(), body("newPassword").isLength({ min: 8, max: 16 }).matches(/[A-Z]/).matches(/[^A-Za-z0-9]/)],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return sendValidationErrors(res, errors);
        const userId = req.user.id;
        const { oldPassword, newPassword } = req.body;
        try {
            const row = await db.get("SELECT password_hash FROM users WHERE id = ?", [userId]);
            if (!row) return res.status(404).json({ error: "User not found" });
            const ok = await bcrypt.compare(oldPassword, row.password_hash);
            if (!ok) return res.status(400).json({ error: "Old password incorrect" });
            const hash = await bcrypt.hash(newPassword, 10);
            await db.run("UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", [hash, userId]);
            return res.json({ changed: true });
        } catch (err) {
            console.error("Change password error:", err);
            return res.status(500).json({ error: "Server error" });
        }
    }
);


