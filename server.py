import os
from flask import Flask, request, jsonify, session, send_from_directory, current_app
from flask_cors import CORS
import sqlite3

APP_HOST = "0.0.0.0"
APP_PORT = int(os.environ.get("PORT", 5000))

SECRET_KEY = os.environ.get("SECRET_KEY", "replace_with_a_random_secret_key")
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "")
PROD = os.environ.get("PROD", "0") in ("1", "true", "True")
DB_PATH = os.environ.get("SQLITE_PATH", "users.db")

app = Flask(__name__, static_folder="public", static_url_path="/")
app.secret_key = SECRET_KEY

if ALLOWED_ORIGINS:
    origins = [o.strip() for o in ALLOWED_ORIGINS.split(",")]
    CORS(app, origins=origins, supports_credentials=True)
else:
    CORS(app, supports_credentials=True)

app.config.update({
    "SESSION_COOKIE_HTTPONLY": True,
    "SESSION_COOKIE_SECURE": PROD,
    "SESSION_COOKIE_SAMESITE": "Lax" if not PROD else "None"
})

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fio TEXT,
        phone TEXT UNIQUE,
        email TEXT,
        cardNumber TEXT,
        dob TEXT,
        gender TEXT,
        avatar TEXT
      )
    """)
    conn.commit()
    conn.close()

init_db()

@app.route("/")
def index():
    return app.send_static_file("index.html")

@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(app.static_folder, filename)

@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json() or request.form
    fio = data.get("fio")
    phone = data.get("phone")
    email = data.get("email")
    card = data.get("cardNumber") or data.get("card")
    dob = data.get("dob")
    gender = data.get("gender")

    if not fio or not phone:
        return jsonify({"error": "fio и phone обязательны"}), 400

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id FROM users WHERE phone = ?", (phone,))
        if cur.fetchone():
            return jsonify({"error": "Пользователь с таким телефоном уже зарегистрирован"}), 400
        cur.execute(
            "INSERT INTO users (fio, phone, email, cardNumber, dob, gender) VALUES (?, ?, ?, ?, ?, ?)",
            (fio, phone, email, card, dob, gender)
        )
        user_id = cur.lastrowid
        conn.commit()
    finally:
        conn.close()

    session.clear()
    session["user_id"] = user_id
    current_app.logger.info("Новый пользователь зарегистрирован: %s (%s)", fio, phone)
    return jsonify({"ok": True, "user_id": user_id})

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json() or request.form
    fio = data.get("fio")
    phone = data.get("phone")

    if not fio or not phone:
        return jsonify({"error": "fio и phone обязательны"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE fio = ? AND phone = ?", (fio, phone))
    row = cur.fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Неверные данные или пользователь не найден"}), 401

    session.clear()
    session["user_id"] = row["id"]
    current_app.logger.info("Вход: %s (%s)", fio, phone)
    return jsonify({"ok": True, "user_id": row["id"]})

@app.route("/api/profile", methods=["GET"])
def api_profile():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Не авторизован"}), 401

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id,fio,phone,email,cardNumber,dob,gender,avatar FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Пользователь не найден"}), 404

    profile = dict(row)
    return jsonify({"ok": True, "profile": profile})

@app.route("/api/profile", methods=["POST"])
def api_profile_update():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Не авторизован"}), 401

    data = request.get_json() or request.form
    fields = []
    params = []
    for k in ("fio","phone","email","cardNumber","dob","gender","avatar"):
        if k in data:
            fields.append(f"{k} = ?")
            params.append(data.get(k))
    if not fields:
        return jsonify({"error": "Нет данных для обновления"}), 400

    params.append(user_id)
    sql = f"UPDATE users SET {', '.join(fields)} WHERE id = ?"
    conn = get_db()
    cur = conn.cursor()
    cur.execute(sql, params)
    conn.commit()
    cur.execute("SELECT id,fio,phone,email,cardNumber,dob,gender,avatar FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()

    current_app.logger.info("Профиль пользователя %s обновлён", user_id)
    return jsonify({"ok": True, "profile": dict(row)})

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True})

if __name__ == "__main__":
    app.run(host=APP_HOST, port=APP_PORT, debug=not PROD)

