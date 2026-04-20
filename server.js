const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const crypto = require('crypto');

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const JWT_SECRET = process.env.JWT_SECRET || 'moneybot-secret-change-in-prod';
const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex'); // 32 bytes
const IV_LENGTH = 16;

app.use(cors({ origin: '*', methods: ['GET', 'POST', 'DELETE', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.options('*', cors());
app.use(express.json());

// --- Encryption helpers ---
function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
  try {
    const [ivHex, encryptedHex] = text.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const encrypted = Buffer.from(encryptedHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
  } catch {
    return text; // fallback for any unencrypted legacy rows
  }
}

// --- DB init ---
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      started_at TIMESTAMP DEFAULT NOW(),
      last_active TIMESTAMP DEFAULT NOW(),
      exchange_count INTEGER DEFAULT 0,
      reached_summary BOOLEAN DEFAULT FALSE
    );
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      session_id INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
      role TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log('Database initialized');
}
initDB();

// --- Auth middleware ---
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// --- Routes ---

app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email',
      [email.toLowerCase(), hashed]
    );
    const token = jwt.sign({ id: result.rows[0].id, email: result.rows[0].email }, JWT_SECRET);
    res.json({ token, email: result.rows[0].email });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Email already registered' });
    res.status(500).json({ error: err.message });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    if (!result.rows.length) return res.status(400).json({ error: 'Invalid email or password' });
    const valid = await bcrypt.compare(password, result.rows[0].password);
    if (!valid) return res.status(400).json({ error: 'Invalid email or password' });
    const token = jwt.sign({ id: result.rows[0].id, email: result.rows[0].email }, JWT_SECRET);
    res.json({ token, email: result.rows[0].email });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete account + all data
app.delete('/account', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [req.user.id]);
    // sessions and messages cascade-delete automatically via ON DELETE CASCADE
    res.json({ success: true, message: 'Account and all data permanently deleted.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/sessions/new', auth, async (req, res) => {
  try {
    const result = await pool.query('INSERT INTO sessions (user_id) VALUES ($1) RETURNING id', [req.user.id]);
    res.json({ sessionId: result.rows[0].id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/sessions', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM sessions WHERE user_id = $1 ORDER BY started_at DESC', [req.user.id]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get messages for a session (decrypted)
app.get('/sessions/:sessionId/messages', auth, async (req, res) => {
  try {
    // Verify session belongs to user
    const session = await pool.query('SELECT * FROM sessions WHERE id = $1 AND user_id = $2', [req.params.sessionId, req.user.id]);
    if (!session.rows.length) return res.status(403).json({ error: 'Unauthorized' });

    const result = await pool.query('SELECT * FROM messages WHERE session_id = $1 ORDER BY created_at ASC', [req.params.sessionId]);
    const decrypted = result.rows.map(m => ({ ...m, content: decrypt(m.content) }));
    res.json(decrypted);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/chat', auth, async (req, res) => {
  const { messages, sessionId, reachedSummary } = req.body;
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
        'anthropic-beta': 'interleaved-thinking-2025-05-14'
      },
      body: JSON.stringify(req.body)
    });
    const data = await response.json();

    if (sessionId) {
      const lastMessage = messages[messages.length - 1];
      // Encrypt before storing
      await pool.query(
        'INSERT INTO messages (session_id, role, content) VALUES ($1, $2, $3)',
        [sessionId, lastMessage.role, encrypt(lastMessage.content)]
      );
      if (data.content?.[0]?.text) {
        await pool.query(
          'INSERT INTO messages (session_id, role, content) VALUES ($1, $2, $3)',
          [sessionId, 'assistant', encrypt(data.content[0].text)]
        );
      }
      await pool.query(
        'UPDATE sessions SET exchange_count = exchange_count + 1, last_active = NOW(), reached_summary = COALESCE($1, reached_summary) WHERE id = $2',
        [reachedSummary || null, sessionId]
      );
    }

    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/', (req, res) => res.send('Money bot backend running.'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
