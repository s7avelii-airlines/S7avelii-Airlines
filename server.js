const express = require("express");
const fs = require("fs");
const path = require("path");
const session = require("express-session");
const bodyParser = require("body-parser");

const app = express();
const PORT = process.env.PORT || 3000;

const USERS_FILE = path.join(__dirname, "users.json");

// ====== Middleware ======
app.use(bodyParser.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    secret: "s7avelii-secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 7 * 24 * 60 * 60 * 1000 }, // 7 дней
  })
);

// ====== Helpers ======
function readUsers() {
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
  } catch {
    return [];
  }
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), "utf8");
}

// ====== Auth ======
app.post("/api/register", (req, res) => {
  const { fio, dob, gender, email, phone, password, card, cardType } = req.body;
  let users = readUsers();

  if (users.find((u) => u.phone === phone)) {
    return res.status(400).json({ error: "Пользователь с таким телефоном уже существует" });
  }

  const newUser = {
    fio,
    dob,
    gender,
    email,
    phone,
    password,
    card,
    cardType,
    avatar: "",
    bonusMiles: 1000,
    cart: [], // корзина по умолчанию
  };

  users.push(newUser);
  saveUsers(users);

  req.session.user = { phone };
  res.json({ success: true, user: newUser });
});

app.post("/api/login", (req, res) => {
  const { fio, phone, password } = req.body;
  let users = readUsers();

  const user = users.find((u) => u.phone === phone && u.password === password);
  if (!user) {
    return res.status(400).json({ error: "Неверные данные" });
  }

  req.session.user = { phone };
  res.json({ success: true, user });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// ====== Profile ======
app.get("/api/profile", (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "Не авторизован" });
  let users = readUsers();
  const user = users.find((u) => u.phone === req.session.user.phone);
  if (!user) return res.status(404).json({ error: "Пользователь не найден" });
  res.json({ user });
});

app.post("/api/update-profile", (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "Не авторизован" });

  let users = readUsers();
  const idx = users.findIndex((u) => u.phone === req.session.user.phone);
  if (idx === -1) return res.status(404).json({ error: "Пользователь не найден" });

  users[idx] = { ...users[idx], ...req.body };
  saveUsers(users);

  res.json({ success: true, user: users[idx] });
});

// ====== Cart ======
app.post("/api/cart/add", (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "Не авторизован" });

  const { product } = req.body;
  if (!product) return res.status(400).json({ error: "Нет товара" });

  let users = readUsers();
  const idx = users.findIndex((u) => u.phone === req.session.user.phone);
  if (idx === -1) return res.status(404).json({ error: "Пользователь не найден" });

  users[idx].cart.push(product);
  saveUsers(users);

  res.json({ success: true, cart: users[idx].cart });
});

app.get("/api/cart", (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "Не авторизован" });

  let users = readUsers();
  const user = users.find((u) => u.phone === req.session.user.phone);
  if (!user) return res.status(404).json({ error: "Пользователь не найден" });

  res.json({ cart: user.cart });
});

// ====== Start ======
app.listen(PORT, () => {
  console.log(`✅ Server started on port ${PORT}`);
});


