const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const PgSession = require('connect-pg-simple')(session);
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// session store in PostgreSQL
app.use(session({
  store: new PgSession({ pool: pool, tableName: 'session' }),
  name: 's7avelii.sid',
  secret: process.env.SESSION_SECRET || 'change-this-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

/* ---------- Helpers ---------- */
const makeId = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
const withoutPassword = user => {
  const copy = { ...user }; delete copy.password; return copy;
};

/* ---------- Auth / Profile ---------- */
app.post('/api/register', async (req, res) => {
  try {
    const { fio, phone, email, password, cardNumber, cardType, dob, gender } = req.body;
    if (!fio || !phone || !password) return res.status(400).json({ error: 'fio, phone и password обязательны' });

    const client = await pool.connect();
    try {
      const { rows } = await client.query('SELECT * FROM users WHERE phone=$1 OR (email=$2 AND $2<>\'\')', [phone, email]);
      if (rows.length > 0) return res.status(400).json({ error: 'Пользователь с таким телефоном/email уже есть' });

      const hashed = await bcrypt.hash(password, 10);
      const id = makeId();
      const result = await client.query(
        `INSERT INTO users (id,fio,phone,email,password,card_number,card_type,dob,gender,avatar,bonus_miles,role,created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,0,'user',NOW()) RETURNING *`,
        [id,fio,phone,email||'',hashed,cardNumber||'',cardType||'',dob||'',gender||'','']
      );
      req.session.userId = result.rows[0].id;
      res.json({ ok: true, user: withoutPassword(result.rows[0]) });
    } finally { client.release(); }
  } catch (err) { console.error(err); res.status(500).json({ error: 'Internal server error' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { phone, email, password } = req.body;
    if ((!phone && !email) || !password) return res.status(400).json({ error: 'Нужен phone/email и пароль' });

    const client = await pool.connect();
    try {
      const { rows } = await client.query('SELECT * FROM users WHERE phone=$1 OR (email=$2 AND $2<>\'\')', [phone,email]);
      if (!rows.length) return res.status(400).json({ error: 'Пользователь не найден' });
      const user = rows[0];
      if (!await bcrypt.compare(password,user.password)) return res.status(400).json({ error: 'Неверный пароль' });
      req.session.userId = user.id;
      res.json({ ok: true, user: withoutPassword(user) });
    } finally { client.release(); }
  } catch (err) { console.error(err); res.status(500).json({ error: 'Internal server error' }); }
});

app.post('/api/logout', (req,res) => {
  req.session.destroy(err => { if(err) console.warn(err); res.clearCookie('s7avelii.sid'); res.json({ok:true}); });
});

app.get('/api/profile', async (req,res) => {
  try {
    if(!req.session.userId) return res.status(401).json({error:'Не авторизован'});
    const { rows } = await pool.query('SELECT * FROM users WHERE id=$1',[req.session.userId]);
    if(!rows.length) return res.status(404).json({error:'Пользователь не найден'});
    res.json({ ok:true, user: withoutPassword(rows[0]) });
  } catch(e){ console.error(e); res.status(500).json({error:'Internal server error'}); }
});

app.post(['/api/profile/update','/api/update-profile'], async (req,res)=>{
  try {
    if(!req.session.userId) return res.status(401).json({error:'Не авторизован'});
    const allowed=['fio','phone','email','cardNumber','cardType','dob','gender','avatar','bonusMiles'];
    const updates=[]; const values=[]; let i=1;
    for(const k of allowed){ if(req.body[k]!==undefined){ updates.push(`${k==='cardNumber'?'card_number':k}=$${i}`); values.push(req.body[k]); i++; }}
    if(!updates.length) return res.json({ok:true});
    values.push(req.session.userId);
    const { rows } = await pool.query(`UPDATE users SET ${updates.join(', ')} WHERE id=$${i} RETURNING *`, values);
    res.json({ ok:true, user: withoutPassword(rows[0]) });
  } catch(e){ console.error(e); res.status(500).json({error:'Internal server error'}); }
});

/* ---------- SPA fallback ---------- */
app.get('*', (req,res) => res.sendFile(path.join(__dirname,'public','index.html')));

/* ---------- Start ---------- */
app.listen(PORT,()=>console.log(`Server running on port ${PORT}`));
