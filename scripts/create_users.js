// scripts/create_users.js
// Usage: node scripts/create_users.js
// Creates/overwrites data/users.json with sample users (passwords hashed with bcrypt)

const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');

const DATA_DIR = path.join(__dirname, '..', 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

const sampleUsers = [
  {
    id: 'admin-' + Date.now().toString(36),
    fio: 'Администратор',
    phone: '+70000000001',
    email: 'admin@s7avelii.example',
    passwordPlain: 'AdminPass123!', // пароль администратора (меняй при необходимости)
    cardNumber: '00000001',
    cardType: 'VIP',
    dob: '01.01.1990',
    gender: 'М',
    avatar: '',
    bonusMiles: 10000,
    role: 'admin',
  },
  {
    id: 'user1-' + Date.now().toString(36),
    fio: 'Иван Иванов',
    phone: '+70000000002',
    email: 'ivan@example.com',
    passwordPlain: 'user1pass',
    cardNumber: '11112222',
    cardType: 'Classic',
    dob: '02.02.1992',
    gender: 'М',
    avatar: '',
    bonusMiles: 120,
    role: 'user',
  },
  {
    id: 'user2-' + Date.now().toString(36),
    fio: 'Мария Петрова',
    phone: '+70000000003',
    email: 'maria@example.com',
    passwordPlain: 'user2pass',
    cardNumber: '33334444',
    cardType: 'Classic',
    dob: '03.03.1993',
    gender: 'Ж',
    avatar: '',
    bonusMiles: 50,
    role: 'user',
  }
];

async function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

async function run() {
  try {
    await ensureDataDir();
    const usersOut = [];

    for (const u of sampleUsers) {
      const hashed = await bcrypt.hash(u.passwordPlain, 10);
      const out = {
        id: u.id,
        fio: u.fio,
        phone: u.phone,
        email: u.email,
        password: hashed,
        cardNumber: u.cardNumber || '',
        cardType: u.cardType || '',
        dob: u.dob || '',
        gender: u.gender || '',
        avatar: u.avatar || '',
        bonusMiles: u.bonusMiles || 0,
        role: u.role || 'user',
        createdAt: new Date().toISOString()
      };
      usersOut.push(out);
    }

    fs.writeFileSync(USERS_FILE, JSON.stringify(usersOut, null, 2), 'utf8');
    console.log('Created', USERS_FILE);
    console.log('Sample users:');
    usersOut.forEach(u => console.log(`  ${u.fio} | ${u.email} | phone:${u.phone} | role:${u.role}`));
    console.log('\nAdmin credentials: email=admin@s7avelii.example password=AdminPass123!');
  } catch (err) {
    console.error('Error creating users.json', err);
    process.exit(1);
  }
}

run();
