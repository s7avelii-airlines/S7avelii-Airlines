import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pkg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

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

// --- Проверка подключения ---
pool.connect()
  .then(c => { console.log("✅ DB connected"); c.release(); })
  .catch(err => console.error("❌ DB connection error:", err));

// --- Инициализация БД ---
async function initDB() {
  try {
    // users
    await pool.query(`DROP TABLE IF EXISTS users CASCADE`);
    await pool.query(`
      CREATE TABLE users (
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
      )
    `);

    // products
    await pool.query(`DROP TABLE IF EXISTS products CASCADE`);
    await pool.query(`
      CREATE TABLE products (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        price INTEGER NOT NULL
      )
    `);

    // orders
    await pool.query(`DROP TABLE IF EXISTS orders CASCADE`);
    await pool.query(`
      CREATE TABLE orders (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        items JSONB,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Seed products
    const r = await pool.query("SELECT COUNT(*) FROM products");
    if(Number(r.rows[0].count) === 0){
      await pool.query(`
        INSERT INTO products (name, price) VALUES
        ('Брелок S7avelii', 500),
        ('Футболка S7avelii', 1200),
        ('Кружка S7avelii', 800),
        ('Модель самолёта', 2500)
      `);
    }

    console.log("✅ DB initialized");
  } catch (err) {
    console.error("DB init failed:", err);
    throw err;
  }
}
initDB().catch(()=>{});

// --- JWT helper ---
function signToken(userId){
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: "7d" });
}

// --- Auth middleware ---
function authMiddleware(req,res,next){
  const h = req.headers.authorization;
  if(!h) return res.status(401).json({error:"No token"});
  const token = h.split(" ")[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.id;
    next();
  } catch(e){
    return res.status(401).json({error:"Invalid token"});
  }
}

// --- Get user by ID ---
async function getUserById(id){
  const { rows } = await pool.query("SELECT * FROM users WHERE id=$1", [id]);
  return rows[0] || null;
}

// --- Routes ---

// Health
app.get("/api/health", async (req,res)=>{
  try{
    await pool.query("SELECT 1");
    res.json({ok:true});
  } catch(e){ res.status(500).json({ok:false,error:e.message}) }
});

// Register
app.post("/api/register", async (req,res)=>{
  try{
    const { fio, email, phone, password, dob, gender, cardNumber, cardType } = req.body;
    if(!fio || !email || !password) return res.status(400).json({error:"fio,email,password required"});

    // check exist
    const check = await pool.query("SELECT id FROM users WHERE email=$1 OR phone=$2", [email, phone]);
    if(check.rows.length) return res.status(400).json({error:"User exists"});

    const hash = await bcrypt.hash(password, 10);
    const ins = await pool.query(
      `INSERT INTO users (fio, full_name, email, phone, password, dob, gender, card_number, card_type)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
      [fio,fio,email,phone,hash,dob||null,gender||null,cardNumber||null,cardType||null]
    );

    const token = signToken(ins.rows[0].id);
    res.json({ token });
  } catch(err){
    console.error("register err:", err);
    res.status(500).json({error:"Registration failed"});
  }
});

// Login
app.post("/api/login", async (req,res)=>{
  try{
    const { identifier, password, phone, email } = req.body;
    let userRow;

    if(phone || identifier){
      const key = phone || identifier;
      const r = await pool.query("SELECT * FROM users WHERE phone=$1", [key]);
      userRow = r.rows[0];
    } else if(email){
      const r = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
      userRow = r.rows[0];
    }

    if(!userRow) return res.status(400).json({error:"User not found"});

    const ok = await bcrypt.compare(password, userRow.password);
    if(!ok) return res.status(400).json({error:"Wrong password"});

    const token = signToken(userRow.id);
    res.json({ token });
  } catch(err){
    console.error("login err:", err);
    res.status(500).json({error:"Login failed"});
  }
});

// Profile
app.get("/api/profile", authMiddleware, async (req,res)=>{
  try{
    const user = await getUserById(req.userId);
    if(!user) return res.status(404).json({error:"Not found"});
    delete user.password;
    res.json(user);
  } catch(err){
    console.error("profile err:", err);
    res.status(500).json({error:"Profile error"});
  }
});

// Products
app.get("/api/products", async (req,res)=>{
  try{
    const r = await pool.query("SELECT * FROM products ORDER BY id");
    res.json(r.rows);
  } catch(err){
    console.error("products err:", err);
    res.status(500).json({error:"Products error"});
  }
});

// Serve static frontend
app.use(express.static("public"));

// Start server
app.listen(PORT, ()=>console.log(`✅ Server started on ${PORT}`));
