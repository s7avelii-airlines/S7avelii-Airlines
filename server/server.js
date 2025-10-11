import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pkg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();
const { Pool } = pkg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const app = express();
app.use(express.json());
app.use(cors({
  origin: process.env.STATIC_ORIGIN || "*",
  credentials: true,
}));

const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret";

app.get("/api/health", async (req,res)=>{
  try{
    await pool.query("SELECT 1");
    res.json({ok:true});
  }catch(e){res.status(500).json({ok:false,error:e.message})}
});

// Проверка подключения к базе
pool.connect()
  .then(client => {
    console.log("✅ Подключение к базе установлено");
    client.release();
  })
  .catch(err => console.error("❌ Ошибка подключения к базе:", err));
