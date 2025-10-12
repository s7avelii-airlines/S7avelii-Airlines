import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pkg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import path from "path";
import fs from "fs";

dotenv.config();
const { Pool } = pkg;

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret";
const STATIC_ORIGIN = process.env.STATIC_ORIGIN || "*";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const app = express();
app.use(express.json());
app.use(cors({
  origin: STATIC_ORIGIN,
  credentials: true,
  methods: ["GET","POST","PUT","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization"]
}));

// Static folder for avatars
const upload = multer({ dest: 'public/avatars/' });
app.use('/avatars', express.static(path.join(process.cwd(), 'public/avatars')));

// --- DB init ---
async function initDB() {
  try {
    // Users
    await pool.query(`CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      fio TEXT NOT NULL,
      full_name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT UNIQUE,
      password TEXT NOT NULL,
      avatar TEXT,
      dob DATE,
      gender TEXT,
      vk TEXT,
      telegram TEXT,
      card_number TEXT,
      card_type TEXT,
      bonus_miles INTEGER DEFAULT 0,
      status_miles INTEGER DEFAULT 0,
      cart JSONB DEFAULT '[]'
    )`);

    // Products
    await pool.query(`CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      price INTEGER NOT NULL
    )`);

    // Orders
    await pool.query(`CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      items JSONB,
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    // Seed products
    const r = await pool.query("SELECT COUNT(*) FROM products");
    if(Number(r.rows[0].count) === 0){
      await pool.query(`INSERT INTO products (name, price) VALUES
        ('Брелок S7avelii', 500),
        ('Футболка S7avelii', 1200),
        ('Кружка S7avelii', 800),
        ('Модель самолёта', 2500)
      `);
    }

    console.log("✅ DB initialized");
  } catch(err){ console.error("DB init failed:", err); }
}
initDB();

// --- JWT helpers ---
function signToken(userId){ return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn:"7d" }); }

function authMiddleware(req,res,next){
  const h = req.headers.authorization;
  if(!h) return res.status(401).json({error:"No token"});
  const token = h.split(" ")[1];
  try { req.userId = jwt.verify(token, JWT_SECRET).id; next(); }
  catch { return res.status(401).json({error:"Invalid token"}); }
}

// --- Routes ---

// Health check
app.get("/api/health", async (req,res)=>{
  try{ await pool.query("SELECT 1"); res.json({ok:true}); } 
  catch(e){ res.status(500).json({ok:false,error:e.message}); }
});

// Register
app.post("/api/register", async (req,res)=>{
  try{
    const { fio, email, phone, password, dob, gender, cardNumber, cardType } = req.body;
    if(!fio || !email || !password) return res.status(400).json({error:"fio,email,password required"});
    const exists = await pool.query("SELECT id FROM users WHERE email=$1 OR phone=$2", [email, phone]);
    if(exists.rows.length) return res.status(400).json({error:"User exists"});
    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query(
      `INSERT INTO users (fio, full_name, email, phone, password, dob, gender, card_number, card_type)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
      [fio,fio,email,phone,hash,dob||null,gender||null,cardNumber||null,cardType||null]
    );
    const token = signToken(r.rows[0].id);
    res.json({ token });
  }catch(err){ console.error("register error", err); res.status(500).json({error:"Registration failed"}); }
});

// Login
app.post("/api/login", async (req,res)=>{
  try{
    const { identifier, password, email, phone } = req.body;
    let user;
    if(identifier || phone){
      const key = identifier || phone;
      const r = await pool.query("SELECT * FROM users WHERE phone=$1", [key]);
      user = r.rows[0];
    } else if(email){
      const r = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
      user = r.rows[0];
    }
    if(!user) return res.status(400).json({error:"User not found"});
    const ok = await bcrypt.compare(password, user.password);
    if(!ok) return res.status(400).json({error:"Wrong password"});
    res.json({ token: signToken(user.id) });
  }catch(err){ console.error("login error", err); res.status(500).json({error:"Login failed"}); }
});

// Profile
app.get("/api/profile", authMiddleware, async (req,res)=>{
  try{
    const { rows } = await pool.query("SELECT * FROM users WHERE id=$1", [req.userId]);
    if(!rows[0]) return res.status(404).json({error:"Not found"});
    const user = {...rows[0]}; delete user.password;
    res.json(user);
  }catch(err){ console.error("profile error", err); res.status(500).json({error:"Profile error"}); }
});

// Update profile
app.put("/api/profile", authMiddleware, async (req,res)=>{
  try{
    const fields = ["fio","dob","gender","email","phone","card_number","card_type"];
    const updates = [];
    const values = [];
    let i=1;
    fields.forEach(f=>{
      if(req.body[f]!==undefined){ updates.push(`${f}=$${i}`); values.push(req.body[f]); i++; }
    });
    if(updates.length===0) return res.status(400).json({error:"Nothing to update"});
    values.push(req.userId);
    await pool.query(`UPDATE users SET ${updates.join(", ")} WHERE id=$${i}`, values);
    res.json({ok:true});
  }catch(err){ console.error("update profile error", err); res.status(500).json({error:"Update failed"}); }
});

// Upload avatar
app.post("/api/profile/avatar", authMiddleware, upload.single("avatar"), async (req,res)=>{
  try{
    if(!req.file) return res.status(400).json({error:"No file"});
    const ext = path.extname(req.file.originalname);
    const newName = `${req.userId}${ext}`;
    const newPath = path.join(req.file.destination, newName);
    fs.renameSync(req.file.path, newPath);
    const avatarUrl = `/avatars/${newName}`;
    await pool.query("UPDATE users SET avatar=$1 WHERE id=$2", [avatarUrl, req.userId]);
    res.json({avatar:avatarUrl});
  }catch(err){ console.error("avatar upload error", err); res.status(500).json({error:"Avatar upload failed"}); }
});

// Products / Shop
app.get("/api/shop", async (req,res)=>{
  try{
    const r = await pool.query("SELECT * FROM products ORDER BY id");
    res.json({products:r.rows});
  }catch(err){ console.error("shop error", err); res.status(500).json({error:"Shop error"}); }
});

// Checkout / Cart
app.post("/api/checkout", authMiddleware, async (req,res)=>{
  try{
    const items = req.body.items || [];
    if(!Array.isArray(items) || items.length===0) return res.status(400).json({error:"Cart empty"});
    await pool.query("INSERT INTO orders (user_id, items) VALUES ($1,$2)", [req.userId, items]);
    await pool.query("UPDATE users SET cart='[]' WHERE id=$1", [req.userId]);
    res.json({ok:true});
  }catch(err){ console.error("checkout error", err); res.status(500).json({error:"Checkout failed"}); }
});

// Serve static frontend
app.use(express.static("public"));

// Start server
app.listen(PORT, ()=>console.log(`✅ Server running on ${PORT}`));
