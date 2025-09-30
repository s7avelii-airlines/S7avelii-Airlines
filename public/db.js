// db.js
const { Pool } = require("pg");
require("dotenv").config();

// Подключение к базе
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // берём из переменных Render
  ssl: { rejectUnauthorized: false } // для Neon обязательно
});

// Тестовое подключение
pool.connect()
  .then(client => {
    console.log("✅ Подключение к базе успешно!");
    client.release();
  })
  .catch(err => {
    console.error("❌ Ошибка подключения к базе:", err.message);
  });

module.exports = pool;
