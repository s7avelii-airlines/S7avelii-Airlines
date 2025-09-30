// server.js
const express = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const path = require("path");
const cors = require("cors");
require("dotenv").config();

const pool = require("./db");

const app = express();
const PORT = process.env.PORT || 3000;

// ===== Middleware =====
app.use(express.json({ limit: "5mb" }));
app.use(cookieParser());
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);

app.use(
  session({
    secret: process.env.SESSION_SECRET || "supersecret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false, // ⚠️ для Render ставь true
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 дней
    },
  })
);

// ===== Middleware для защиты =====
function authRequired(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ message: "Не авторизован" });
  }
  next();
}

// ===== API =====

// Регистрация
app.post("/api/register", async (req, res) => {
  const { email, password, fio, phone, gender, card, cardType } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "Email и пароль обязательны" });
  }

  try {
    const exists = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
    if (exists.rows.length > 0) {
      return res.status(400).json({ message: "Пользователь уже существует" });
    }

    const hashed = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users 
        (email, password, full_name, phone, gender, card_number, card_type, bonus_miles, role) 
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [
        email,
        hashed,
        fio || "",
        phone || "",
        gender || "",
        card || "",
        cardType || "Classic",
        1000,
        "user",
      ]
    );

    const newUser = result.rows[0];
    req.session.userId = newUser.id;
    res.json({ message: "Регистрация успешна", user: newUser });
  } catch (err) {
    console.error("Ошибка регистрации:", err.message);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Логин
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "Email и пароль обязательны" });
  }

  try {
    const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (result.rows.length === 0) return res.status(400).json({ message: "Пользователь не найден" });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: "Неверный пароль" });

    req.session.userId = user.id;
    res.json({ message: "Вход успешен", user });
  } catch (err) {
    console.error("Ошибка входа:", err.message);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Получить текущего пользователя
app.get("/api/me", authRequired, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM users WHERE id=$1", [req.session.userId]);
    res.json(result.rows[0] || null);
  } catch (err) {
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Обновление профиля
app.post("/api/profile", authRequired, async (req, res) => {
  const { fio, phone, email, gender, card, cardType } = req.body;

  try {
    const result = await pool.query(
      `UPDATE users 
       SET full_name=$1, phone=$2, email=$3, gender=$4, card_number=$5, card_type=$6 
       WHERE id=$7 RETURNING *`,
      [fio, phone, email, gender, card, cardType, req.session.userId]
    );
    res.json({ message: "Профиль обновлен", user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Получить всех пользователей (для админа)
app.get("/api/users", authRequired, async (req, res) => {
  const current = await pool.query("SELECT role FROM users WHERE id=$1", [req.session.userId]);
  if (current.rows.length === 0 || current.rows[0].role !== "admin") {
    return res.status(403).json({ message: "Нет доступа" });
  }
  const result = await pool.query("SELECT * FROM users");
  res.json(result.rows);
});

// Выйти
app.post("/api/logout", authRequired, (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ message: "Ошибка выхода" });
    res.clearCookie("connect.sid");
    res.json({ message: "Выход выполнен" });
  });
});

// ===== Статика =====
app.use(express.static(path.join(__dirname, "public")));

app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
