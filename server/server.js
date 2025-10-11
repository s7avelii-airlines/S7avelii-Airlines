// server.js
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pkg from "pg";

dotenv.config();
const { Pool } = pkg;

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret";
const STATIC_ORIGIN = process.env.STATIC_ORIGIN || "http://localhost:3000"; // <- точный домен фронта!

// Настройка PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const app = express();
app.use(express.json());

// CORS для credentials
app.use(cors({
  origin: STATIC_ORIGIN,
  methods: ["GET","POST","PUT","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization"],
  credentials: true
}));

// --- Health check ---
app.get("/api/health", async (req,res)=>{
  try{
    await pool.query("SELECT 1");
    res.json({ok:true});
  }catch(err){
    console.error("health err:", err);
    res.status(500).json({ok:false, error:err.message});
  }
});

// --- Инициализация БД ---
async function initDB(){
  try{
    // Удаляем старые таблицы (если нужно)
    await pool.query("DROP TABLE IF EXISTS orders");
    await pool.query("DROP TABLE IF EXISTS products");
    await pool.query("DROP TABLE IF EXISTS users");

    // Полная таблица users
    await pool.query(`
      CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        fio TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        dob DATE,
        gender TEXT,
        avatar TEXT,
        card_number TEXT,
        card_type TEXT,
        bonus_miles INTEGER DEFAULT 0,
        status_miles INTEGER DEFAULT 0,
        cart JSONB DEFAULT '[]',
        vk TEXT,
        telegram TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Таблица products
    await pool.query(`
      CREATE TABLE products (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        price INTEGER NOT NULL
      );
    `);

    // Таблица orders
    await pool.query(`
      CREATE TABLE orders (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        items JSONB,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Seed products
    const r = await pool.query("SELECT COUNT(*) FROM products");
    if(Number(r.rows[0].count) === 0){
      await pool.query(`
        INSERT INTO products (name, price) VALUES
        ('Брелок S7avelii', 500),
        ('Футболка S7avelii', 1200),
        ('Кружка S7avelii', 800),
        ('Модель самолёта', 2500);
      `);
    }

    console.log("✅ DB initialized");
  }catch(err){
    console.error("DB init failed:", err);
    throw err;
  }
}
initDB().catch(()=>{});

// --- JWT ---
function signToken(userId){
  return jwt.sign({id:userId}, JWT_SECRET, {expiresIn:"7d"});
}

// --- Auth middleware ---
function authMiddleware(req,res,next){
  const h = req.headers.authorization;
  if(!h) return res.status(401).json({error:"No token"});
  const token = h.split(" ")[1];
  try{
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.id;
    next();
  }catch{
    res.status(401).json({error:"Invalid token"});
  }
}

// --- Register ---
app.post("/api/register", async (req,res)=>{
  try{
    const {fio,email,phone,password,dob,gender,cardNumber,cardType} = req.body;
    if(!fio||!email||!phone||!password) return res.status(400).json({error:"fio,email,phone,password required"});

    // Проверяем существование
    const check = await pool.query("SELECT id FROM users WHERE email=$1 OR phone=$2", [email,phone]);
    if(check.rows.length) return res.status(400).json({error:"Пользователь уже существует"});

    const hash = await bcrypt.hash(password,10);
    const r = await pool.query(`
      INSERT INTO users (fio,email,phone,password,dob,gender,card_number,card_type)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
      RETURNING id
    `, [fio,email,phone,hash,dob||null,gender||null,cardNumber||null,cardType||null]);

    const token = signToken(r.rows[0].id);
    res.json({token});
  }catch(err){
    console.error("register err:",err);
    res.status(500).json({error:"Registration failed"});
  }
});

// --- Login ---
app.post("/api/login", async (req,res)=>{
  try{
    const {phone,password} = req.body;
    if(!phone||!password) return res.status(400).json({error:"phone,password required"});

    const r = await pool.query("SELECT * FROM users WHERE phone=$1", [phone]);
    if(!r.rows[0]) return res.status(400).json({error:"Пользователь не найден"});

    const ok = await bcrypt.compare(password, r.rows[0].password);
    if(!ok) return res.status(400).json({error:"Неверный пароль"});

    const token = signToken(r.rows[0].id);
    res.json({token});
  }catch(err){
    console.error("login err:",err);
    res.status(500).json({error:"Login failed"});
  }
});

// --- Profile ---
app.get("/api/profile", authMiddleware, async (req,res)=>{
  try{
    const r = await pool.query("SELECT * FROM users WHERE id=$1", [req.userId]);
    const user = r.rows[0];
    if(!user) return res.status(404).json({error:"Not found"});
    delete user.password;
    res.json(user);
  }catch(err){
    console.error("profile err:",err);
    res.status(500).json({error:"Profile error"});
  }
});

// --- Products ---
app.get("/api/products", async (req,res)=>{
  try{
    const r = await pool.query("SELECT * FROM products ORDER BY id");
    res.json(r.rows);
  }catch(err){
    console.error("products err:",err);
    res.status(500).json({error:"Products error"});
  }
});

// --- Cart ---
app.get("/api/cart", authMiddleware, async (req,res)=>{
  try{
    const r = await pool.query("SELECT cart FROM users WHERE id=$1", [req.userId]);
    res.json(r.rows[0].cart || []);
  }catch(err){
    console.error("cart.get err:",err);
    res.status(500).json({error:"Cart error"});
  }
});

app.post("/api/cart/add", authMiddleware, async (req,res)=>{
  try{
    const {id} = req.body;
    const p = (await pool.query("SELECT id,name,price FROM products WHERE id=$1",[id])).rows[0];
    if(!p) return res.status(404).json({error:"Product not found"});

    const r = await pool.query("SELECT cart FROM users WHERE id=$1", [req.userId]);
    const cart = r.rows[0].cart || [];
    const found = cart.find(x=>x.id===p.id);
    if(found) found.qty = (found.qty||1)+1;
    else cart.push({id:p.id,name:p.name,price:p.price,qty:1});
    await pool.query("UPDATE users SET cart=$1 WHERE id=$2", [JSON.stringify(cart), req.userId]);
    res.json({ok:true});
  }catch(err){
    console.error("cart.add err:",err);
    res.status(500).json({error:"Cart add error"});
  }
});

// --- Checkout ---
app.post("/api/cart/checkout", authMiddleware, async (req,res)=>{
  try{
    const r = await pool.query("SELECT cart FROM users WHERE id=$1", [req.userId]);
    const cart = r.rows[0].cart || [];
    if(!cart.length) return res.status(400).json({error:"Cart empty"});

    await pool.query("INSERT INTO orders (user_id, items) VALUES ($1,$2)", [req.userId, JSON.stringify(cart)]);
    await pool.query("UPDATE users SET cart='[]', bonus_miles=COALESCE(bonus_miles,0)+100 WHERE id=$1", [req.userId]);
    res.json({ok:true});
  }catch(err){
    console.error("checkout err:",err);
    res.status(500).json({error:"Checkout error"});
  }
});

// --- Orders ---
app.get("/api/orders", authMiddleware, async (req,res)=>{
  try{
    const r = await pool.query("SELECT * FROM orders WHERE user_id=$1 ORDER BY id DESC", [req.userId]);
    res.json(r.rows);
  }catch(err){
    console.error("orders err:",err);
    res.status(500).json({error:"Orders error"});
  }
});

// --- Static files ---
app.use(express.static("public"));

app.listen(PORT, ()=>console.log(`✅ Server running on port ${PORT}`));


