const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: 'polytrack-secret', resave: false, saveUninitialized: false }));

const DB_FILE = path.join(__dirname, 'users.db');
const VIDEOS_DIR = path.join(__dirname, 'videos');
if (!fs.existsSync(VIDEOS_DIR)) fs.mkdirSync(VIDEOS_DIR);

const upload = multer({ dest: VIDEOS_DIR });

const db = new sqlite3.Database(DB_FILE);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT,
    is_admin INTEGER DEFAULT 0,
    suspended_until INTEGER DEFAULT 0,
    ban_reason TEXT
  )`);

  const insert = db.prepare('INSERT OR IGNORE INTO users(username,password,is_admin) VALUES(?,?,?)');
  // seed admin and a sample user
  const adminPass = bcrypt.hashSync('adminpass', 8);
  insert.run('ADMIN-0001', adminPass, 1);
  const userPass = bcrypt.hashSync('password', 8);
  insert.run('SRM-1(ST)2345', userPass, 0);
  insert.finalize();
});

// serve videos static
app.use('/videos', express.static(VIDEOS_DIR));

// serve only assets from public (CSS, client JS) at /assets
app.use('/assets', express.static(path.join(__dirname, 'public')));

// expose root game assets (bundles, audio, images, lib, tracks) under /assets/game
app.use('/assets/game', express.static(path.join(__dirname)));

// Map common game asset folders to root paths so main.bundle.js can fetch them
app.use('/images', express.static(path.join(__dirname, 'images')));
app.use('/audio', express.static(path.join(__dirname, 'audio')));
app.use('/models', express.static(path.join(__dirname, 'models')));
app.use('/tracks', express.static(path.join(__dirname, 'tracks')));
app.use('/lib', express.static(path.join(__dirname, 'lib')));

// serve forced_square.json and similar root json files
app.get('/forced_square.json', (req, res) => {
  const p = path.join(__dirname, 'forced_square.json');
  if (fs.existsSync(p)) return res.sendFile(p);
  res.status(404).end();
});

// serve font files from repo root when requested (hash filenames)
app.get(['/*.woff','/*.woff2','/*.ttf'], (req, res) => {
  const f = path.join(__dirname, req.path.replace(/^\//, ''));
  if (fs.existsSync(f)) return res.sendFile(f);
  res.status(404).end();
});

// public home and login are accessible
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'home.html')));
app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));

// protected routes: require login/admin accordingly
app.get('/index.html', requireLogin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'game', 'index.html')));
app.get('/game.html', requireLogin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'game.html')));
app.get('/tiktok.html', requireLogin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'tiktok.html')));
app.get('/admin.html', requireAdmin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

function requireLogin(req, res, next) {
  if (!req.session || !req.session.user) return res.status(401).json({ error: 'not_logged_in' });
  // check current suspension status from DB
  const uid = req.session.user.id;
  db.get('SELECT suspended_until, ban_reason FROM users WHERE id = ?', [uid], (err, row) => {
    if (err) return res.status(500).json({ error: 'db' });
    if (!row) {
      // user removed; destroy session
      req.session.destroy(()=>{});
      return res.status(401).json({ error: 'not_logged_in' });
    }
    if (row.suspended_until && Date.now() < row.suspended_until) {
      // session is still active but user is suspended; destroy session and inform client
      const reason = row.ban_reason || null;
      req.session.destroy(() => {
        return res.status(403).json({ error: 'suspended', reason, until: row.suspended_until });
      });
      return;
    }
    // not suspended, continue
    next();
  });
}

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.user) return res.status(401).json({ error: 'not_logged_in' });
  const uid = req.session.user.id;
  db.get('SELECT is_admin, suspended_until, ban_reason FROM users WHERE id = ?', [uid], (err, row) => {
    if (err) return res.status(500).json({ error: 'db' });
    if (!row) {
      req.session.destroy(()=>{});
      return res.status(401).json({ error: 'not_logged_in' });
    }
    if (row.suspended_until && Date.now() < row.suspended_until) {
      req.session.destroy(() => {
        return res.status(403).json({ error: 'suspended', reason: row.ban_reason || null, until: row.suspended_until });
      });
      return;
    }
    if (!row.is_admin) return res.status(403).json({ error: 'forbidden' });
    next();
  });
}

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
    if (err) return res.status(500).json({ error: 'db' });
    if (!row) return res.status(400).json({ error: 'invalid' });
    if (row.suspended_until && Date.now() < row.suspended_until) {
      return res.status(403).json({ error: 'suspended', reason: row.ban_reason, until: row.suspended_until });
    }
    if (!bcrypt.compareSync(password, row.password)) return res.status(400).json({ error: 'invalid' });
    req.session.user = { id: row.id, username: row.username, is_admin: !!row.is_admin };
    res.json({ ok: true, username: row.username, is_admin: !!row.is_admin });
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', (req, res) => {
  res.json({ user: req.session.user || null });
});

app.post('/api/admin/add-user', requireAdmin, (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'missing' });
  const hash = bcrypt.hashSync(password, 8);
  db.run('INSERT INTO users(username,password,is_admin) VALUES(?,?,0)', [username, hash], function (err) {
    if (err) return res.status(500).json({ error: 'db' });
    res.json({ ok: true, id: this.lastID });
  });
});

app.post('/api/admin/ban', requireAdmin, (req, res) => {
  const { username, hours, reason } = req.body;
  const hoursNum = Number(hours) || 0;
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
    if (err) return res.status(500).json({ error: 'db' });
    if (!row) return res.status(404).json({ error: 'not_found' });
    const until = hoursNum > 0 ? Date.now() + hoursNum * 3600 * 1000 : 0;
    db.run('UPDATE users SET suspended_until = ?, ban_reason = ? WHERE username = ?', [until, reason || null, username], (e) => {
      if (e) return res.status(500).json({ error: 'db' });
      // try to destroy any active sessions for this user (best-effort)
      try{
        if (req.sessionStore && typeof req.sessionStore.all === 'function'){
          req.sessionStore.all((seErr, sessions) => {
            if (!seErr && sessions) {
              Object.keys(sessions).forEach(sid => {
                let s = sessions[sid];
                try{
                  if (typeof s === 'string') s = JSON.parse(s);
                }catch(_){}
                if (s && s.user && s.user.id === row.id) {
                  req.sessionStore.destroy(sid, () => {});
                }
              });
            }
          });
        }
      }catch(_){ }
      res.json({ ok: true, suspended_until: until });
    });
  });
});

app.get('/api/users', requireAdmin, (req, res) => {
  db.all('SELECT id,username,is_admin,suspended_until,ban_reason FROM users', (err, rows) => {
    if (err) return res.status(500).json({ error: 'db' });
    res.json({ users: rows });
  });
});

app.get('/api/videos', (req, res) => {
  fs.readdir(VIDEOS_DIR, (err, files) => {
    if (err) return res.json({ videos: [] });
    const movs = files.filter(f => f.toLowerCase().endsWith('.mov'));
    res.json({ videos: movs });
  });
});

app.post('/api/admin/upload', requireAdmin, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'nofile' });
  // keep filename as uploaded name if provided
  const dest = path.join(VIDEOS_DIR, req.file.originalname || req.file.filename);
  fs.rename(req.file.path, dest, (err) => {
    if (err) return res.status(500).json({ error: 'mv' });
    res.json({ ok: true, file: req.file.originalname });
  });
});

// serve project manifest at root so game can fetch /manifest.json
app.get('/manifest.json', (req, res) => {
  const mf = path.join(__dirname, 'manifest.json');
  if (fs.existsSync(mf)) return res.sendFile(mf);
  res.status(404).end();
});

// serve main bundles from repo root for compatibility with original index references
app.get('/main.bundle.js', (req, res) => {
  const f = path.join(__dirname, 'main.bundle.js');
  if (fs.existsSync(f)) return res.sendFile(f);
  res.status(404).end();
});
app.get('/simulation_worker.bundle.js', (req, res) => {
  const f = path.join(__dirname, 'simulation_worker.bundle.js');
  if (fs.existsSync(f)) return res.sendFile(f);
  res.status(404).end();
});

app.listen(PORT, () => console.log('Server running on http://localhost:' + PORT));
