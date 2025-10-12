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
const avatarDir = path.join(process.cwd(), "public/avatars");
if(!fs.existsSync(avatarDir)) fs.mkdirSync(avatarDir, { recursive: true });
app.use("/avatars", express.static(avatarDir));

// Multer setup
const upload = multer({ dest: avatarDir });

// JWT helper
function signToken(userId){
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: "7d" });
}

// Auth middleware
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

// --- User API ---

app.post("/api/register", async (req,res)=>{
  try{
    const { fio, email, phone, password } = req.body;
    if(!fio || !email || !password) return res.status(400).json({error:"fio,email,password required"});
    const check = await pool.query("SELECT id FROM users WHERE email=$1 OR phone=$2", [email, phone]);
    if(check.rows.length) return res.status(400).json({error:"User exists"});
    const hash = await bcrypt.hash(password, 10);
    const ins = await pool.query(
      `INSERT INTO users (fio, full_name, email, phone, password) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
      [fio,fio,email,phone,hash]
    );
    const token = signToken(ins.rows[0].id);
    res.json({ token });
  }catch(err){ console.error(err); res.status(500).json({error:"Registration failed"}); }
});

app.post("/api/login", async (req,res)=>{
  try{
    const { identifier, password } = req.body;
    let r = await pool.query("SELECT * FROM users WHERE email=$1 OR phone=$2", [identifier, identifier]);
    const user = r.rows[0];
    if(!user) return res.status(400).json({error:"User not found"});
    const ok = await bcrypt.compare(password, user.password);
    if(!ok) return res.status(400).json({error:"Wrong password"});
    const token = signToken(user.id);
    res.json({ token });
  }catch(err){ console.error(err); res.status(500).json({error:"Login failed"}); }
});

app.get("/api/profile", authMiddleware, async (req,res)=>{
  const r = await pool.query("SELECT id,fio,email,phone,avatar,dob,gender,card_number,card_type,bonus_miles,status_miles FROM users WHERE id=$1", [req.userId]);
  res.json(r.rows[0]);
});

app.post("/api/profile/update", authMiddleware, async (req,res)=>{
  const { fio, email, phone, dob, gender, cardNumber, cardType } = req.body;
  await pool.query(
    `UPDATE users SET fio=$1,email=$2,phone=$3,dob=$4,gender=$5,card_number=$6,card_type=$7 WHERE id=$8`,
    [fio,email,phone,dob,gender,cardNumber,cardType,req.userId]
  );
  const r = await pool.query("SELECT id,fio,email,phone,avatar,dob,gender,card_number,card_type,bonus_miles,status_miles FROM users WHERE id=$1", [req.userId]);
  res.json(r.rows[0]);
});

app.post("/api/profile/avatar", authMiddleware, upload.single("avatar"), async (req,res)=>{
  if(!req.file) return res.status(400).json({error:"No file"});
  const fileName = req.file.filename;
  await pool.query("UPDATE users SET avatar=$1 WHERE id=$2", [`/avatars/${fileName}`, req.userId]);
  res.json({ avatar: `/avatars/${fileName}` });
});

// --- Products API ---
app.get("/api/shop", async (req,res)=>{
  const r = await pool.query("SELECT * FROM products ORDER BY id");
  res.json({ products: r.rows });
});

// --- Orders API ---
app.post("/api/checkout", authMiddleware, async (req,res)=>{
  const items = req.body.items || [];
  await pool.query("INSERT INTO orders (user_id, items) VALUES ($1,$2)", [req.userId, JSON.stringify(items)]);
  res.json({ ok:true });
});

// Serve static frontend
app.use(express.static("public"));

app.listen(PORT, ()=>console.log(`✅ Server running on ${PORT}`));
