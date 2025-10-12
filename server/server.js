import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import multer from "multer";
import pg from "pg";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "super_secret_key";

// ====== PostgreSQL ======
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ====== Middleware ======
app.use(cors());
app.use(bodyParser.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ====== Хранилище для multer ======
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) =>
    cb(null, Date.now() + "-" + Math.round(Math.random() * 1e9) + path.extname(file.originalname)),
});
const upload = multer({ storage });

// ====== JWT Middleware ======
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "Нет токена" });
  const token = header.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    res.status(401).json({ error: "Неверный токен" });
  }
}

// ====== Инициализация таблицы ======
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      fio TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT,
      password TEXT NOT NULL,
      dob DATE,
      gender TEXT,
      card_number TEXT,
      card_type TEXT,
      avatar TEXT,
      bonus_miles INTEGER DEFAULT 0,
      status_miles INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log("✅ Таблица users готова");
}
initDB();

// ====== Регистрация ======
app.post("/api/register", async (req, res) => {
  try {
    const { fio, email, phone, password, dob, gender, cardNumber, cardType } = req.body;
    if (!fio || !email || !password)
      return res.status(400).json({ error: "Заполните все обязательные поля" });

    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (fio, email, phone, password, dob, gender, card_number, card_type)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [fio, email, phone, hash, dob, gender, cardNumber, cardType]
    );

    const user = result.rows[0];
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "30d" });
    delete user.password;
    res.json({ token, user });
  } catch (err) {
    console.error("Ошибка регистрации:", err);
    res.status(500).json({ error: "Ошибка регистрации" });
  }
});

// ====== Вход ======
app.post("/api/login", async (req, res) => {
  try {
    const { identifier, password } = req.body;
    const query =
      "SELECT * FROM users WHERE email=$1 OR phone=$1 LIMIT 1";
    const { rows } = await pool.query(query, [identifier]);
    const user = rows[0];
    if (!user) return res.status(400).json({ error: "Пользователь не найден" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: "Неверный пароль" });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "30d" });
    delete user.password;
    res.json({ token, user });
  } catch (err) {
    console.error("Ошибка входа:", err);
    res.status(500).json({ error: "Ошибка входа" });
  }
});

// ====== Получение профиля ======
app.get("/api/profile", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id=$1", [req.userId]);
    const user = rows[0];
    if (!user) return res.status(404).json({ error: "Пользователь не найден" });
    delete user.password;
    res.json({ user });
  } catch (err) {
    console.error("Ошибка профиля:", err);
    res.status(500).json({ error: "Ошибка получения профиля" });
  }
});

// ====== Обновление профиля ======
app.put("/api/profile", authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    const allowed = ["fio", "email", "phone", "dob", "gender", "card_number", "card_type"];
    const updates = [];
    const values = [];
    let idx = 1;

    for (const field of allowed) {
      if (req.body[field] !== undefined) {
        updates.push(`${field} = $${idx++}`);
        values.push(req.body[field]);
      }
    }

    if (updates.length === 0)
      return res.status(400).json({ error: "Нет данных для обновления" });

    values.push(userId);
    const query = `UPDATE users SET ${updates.join(", ")} WHERE id = $${idx} RETURNING *`;
    const { rows } = await pool.query(query, values);
    const user = rows[0];
    delete user.password;
    res.json({ user });
  } catch (err) {
    console.error("Ошибка изменения профиля:", err);
    res.status(500).json({ error: "Ошибка изменения профиля" });
  }
});

// ====== Загрузка аватара ======
app.post("/api/profile/avatar", authMiddleware, upload.single("avatar"), async (req, res) => {
  try {
    const filePath = `/uploads/${req.file.filename}`;
    await pool.query("UPDATE users SET avatar=$1 WHERE id=$2", [filePath, req.userId]);
    res.json({ avatar: filePath });
  } catch (err) {
    console.error("Ошибка загрузки аватара:", err);
    res.status(500).json({ error: "Ошибка загрузки аватара" });
  }
});

// ====== Проверка токена при автологине ======
app.get("/api/auto-login", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id=$1", [req.userId]);
    const user = rows[0];
    if (!user) return res.status(404).json({ error: "Пользователь не найден" });
    delete user.password;
    res.json({ user });
  } catch (err) {
    console.error("Ошибка авто-входа:", err);
    res.status(500).json({ error: "Ошибка авто-входа" });
  }
});

// ====== Маршрут по умолчанию ======
app.get("/", (req, res) => {
  res.send("✅ S7avelii Airlines server is running.");
});

// ====== Запуск ======
app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
