require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const fs = require('fs');

const { DATABASE_URL, ADMIN_PASSWORD, TOKEN_SECRET } = process.env;
if (!ADMIN_PASSWORD || !TOKEN_SECRET) {
  console.error('ناقص إعدادات في ملف .env: لازم ADMIN_PASSWORD و TOKEN_SECRET');
  process.exit(1);
}

const uploadDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({ 
  storage: storage,
  limits: { fileSize: 500 * 1024 * 1024 } // حد أقصى 500 ميجا للفيديو
});

let pool;
async function setupDb() {
  if (DATABASE_URL && /^postgres(ql)?:\/\//i.test(DATABASE_URL)) {
    pool = new Pool({
      connectionString: DATABASE_URL,
      ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : false,
    });
    await pool.query('SELECT 1');
    console.log('الداتا بيز: PostgreSQL (أونلاين)');
  } else {
    const { PGlite } = await import('@electric-sql/pglite');
    const db = new PGlite(path.join(__dirname, 'data'));
    await db.waitReady;
    pool = { query: (sql, params) => db.query(sql, params), exec: (sql) => db.exec(sql) };
    console.log('الداتا بيز: محلية على جهازك (مجلد data)');
  }
}

const app = express();
app.set('trust proxy', 1);

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', process.env.ALLOWED_ORIGIN || '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.get('/', (req, res) => res.json({ ok: true, name: 'aldahiha-api' }));
app.use(express.json({ limit: '20kb' }));
app.use('/uploads', express.static(uploadDir));

const wrap = (fn) => (req, res, next) => fn(req, res, next).catch(next);
const fail = (res, status, error) => res.status(status).json({ error });

const normName = (s) =>
  String(s || '')
    .trim()
    .replace(/\s+/g, ' ')
    .replace(/[أإآ]/g, 'ا')
    .replace(/ى/g, 'ي')
    .replace(/ة/g, 'ه')
    .toLowerCase();

const str = (v, max) => typeof v === 'string' && v.trim().length > 0 && v.trim().length <= max;
const phoneOk = (v) => typeof v === 'string' && /^[0-9+\s-]{7,20}$/.test(v.trim());

const safeEqual = (a, b) => {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
};

function signToken() {
  const payload = Buffer.from(JSON.stringify({ exp: Date.now() + 12 * 3600 * 1000 })).toString('base64url');
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}
function verifyToken(token) {
  const [payload, sig] = String(token || '').split('.');
  if (!payload || !sig) return false;
  const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('base64url');
  if (!safeEqual(sig, expected)) return false;
  try {
    return JSON.parse(Buffer.from(payload, 'base64url').toString()).exp > Date.now();
  } catch {
    return false;
  }
}
function adminAuth(req, res, next) {
  const t = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!verifyToken(t)) return fail(res, 401, 'الجلسة انتهت، ادخل تاني.');
  next();
}

const CODE_PREFIX = String(process.env.CODE_PREFIX ?? '202611').trim();

async function authStudent(name, code) {
  if (typeof name !== 'string' || typeof code !== 'string') return null;
  const { rows } = await pool.query("SELECT id, name FROM students WHERE code = $1 AND status = 'confirmed'", [
    code.trim().toUpperCase(),
  ]);
  const s = rows[0];
  return s && normName(s.name) === normName(name) ? s : null;
}

const limiter = (max, windowMin, extra = {}) =>
  rateLimit({
    windowMs: windowMin * 60 * 1000,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'محاولات كتير، استنى شوية وحاول تاني.' },
    ...extra,
  });
const registerLimit = limiter(20, 60);
const loginLimit = limiter(10, 15, { skipSuccessfulRequests: true });
const studentLimit = limiter(40, 15, { skipSuccessfulRequests: true });
const attendLimit = limiter(60, 15);

app.post('/api/register', registerLimit, wrap(async (req, res) => {
  const b = req.body || {};
  const age = Number(b.age);
  if (!str(b.name, 100) || !str(b.school, 120) || !str(b.address, 200) || !str(b.parentJob, 100))
    return fail(res, 400, 'راجع البيانات: في خانة فاضية أو طويلة زيادة.');
  if (!Number.isInteger(age) || age < 5 || age > 25) return fail(res, 400, 'السن غير صحيح.');
  if (!phoneOk(b.parentPhone) || !phoneOk(b.studentPhone)) return fail(res, 400, 'رقم التليفون غير صحيح.');
  await pool.query(
    `INSERT INTO students (name, age, school, address, parent_job, parent_phone, student_phone)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [b.name.trim(), age, b.school.trim(), b.address.trim(), b.parentJob.trim(), b.parentPhone.trim(), b.studentPhone.trim()]
  );
  res.json({ ok: true });
}));

app.post('/api/student/login', studentLimit, wrap(async (req, res) => {
  const s = await authStudent(req.body?.name, req.body?.code);
  if (!s) return fail(res, 401, 'الاسم أو الكود غير صحيح، أو التسجيل لسه متأكدش.');
  const { rows } = await pool.query('SELECT id, week, title FROM lectures ORDER BY week, id');
  res.json({ lectures: rows });
}));

app.post('/api/attend', attendLimit, wrap(async (req, res) => {
  const s = await authStudent(req.body?.name, req.body?.code);
  if (!s) return fail(res, 401, 'الكود غير صحيح.');
  const lectureId = Number(req.body?.lectureId);
  if (!Number.isInteger(lectureId)) return fail(res, 400, 'محاضرة غير صحيحة.');
  const l = (await pool.query('SELECT url FROM lectures WHERE id = $1', [lectureId])).rows[0];
  if (!l) return fail(res, 404, 'المحاضرة مش موجودة.');
  await pool.query(
    'INSERT INTO attendance (student_id, lecture_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
    [s.id, lectureId]
  );
  res.json({ url: l.url });
}));

app.post('/api/admin/login', loginLimit, wrap(async (req, res) => {
  const p = req.body?.password;
  if (typeof p !== 'string' || !safeEqual(p, ADMIN_PASSWORD)) return fail(res, 401, 'كلمة السر غلط.');
  res.json({ token: signToken() });
}));

app.get('/api/admin/students', adminAuth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, name, age, school, address,
            parent_job AS "parentJob", parent_phone AS "parentPhone", student_phone AS "studentPhone",
            status, code
     FROM students ORDER BY id DESC`
  );
  res.json(rows);
}));

app.post('/api/admin/students/:id/confirm', adminAuth, wrap(async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return fail(res, 400, 'رقم غير صحيح.');
  for (let i = 0; i < 5; i++) {
    const cur = (await pool.query('SELECT code FROM students WHERE id = $1', [id])).rows[0];
    if (!cur) return fail(res, 404, 'الطالب مش موجود.');
    if (cur.code) {
      await pool.query("UPDATE students SET status = 'confirmed' WHERE id = $1", [id]);
      return res.json({ code: cur.code });
    }
    const next = Number((await pool.query('SELECT COALESCE(MAX(seq), 0) + 1 AS n FROM students')).rows[0].n);
    const code = `${CODE_PREFIX}${next}`;
    try {
      const { rows } = await pool.query(
        "UPDATE students SET status = 'confirmed', seq = $2, code = $3 WHERE id = $1 AND code IS NULL RETURNING code",
        [id, next, code]
      );
      if (rows[0]) return res.json({ code: rows[0].code });
    } catch (e) {
      if (e.code !== '23505') throw e;
    }
  }
  fail(res, 500, 'تعذّر توليد الكود، حاول تاني.');
}));

app.delete('/api/admin/students/:id', adminAuth, wrap(async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return fail(res, 400, 'رقم غير صحيح.');
  await pool.query('DELETE FROM students WHERE id = $1', [id]);
  res.json({ ok: true });
}));

app.get('/api/admin/lectures', adminAuth, wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT id, week, title, url FROM lectures ORDER BY week, id');
  res.json(rows);
}));

/* مسار إضافة المحاضرة بتصحيح تلقائي مرن لأرقام الأسابيع منعاً لأي خطأ */
app.post('/api/admin/lectures', adminAuth, upload.single('video'), wrap(async (req, res) => {
  const { week, title } = req.body || {};
  
  let w = parseInt(week, 10);
  if (isNaN(w) || w <= 0) {
    w = 1; // قيمة افتراضية آمنة لو رقم الأسبوع جه فاضي أو غلط
  }

  if (!str(title, 300)) return fail(res, 400, 'اكتب عنوان المحاضرة.');
  if (!req.file) return fail(res, 400, 'من فضلك اختر ملف فيديو المحاضرة.');

  const url = `/uploads/${req.file.filename}`;
  await pool.query('INSERT INTO lectures (week, title, url) VALUES ($1,$2,$3)', [w, title.trim(), url]);
  res.json({ ok: true });
}));

app.delete('/api/admin/lectures/:id', adminAuth, wrap(async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return fail(res, 400, 'رقم غير صحيح.');
  
  const lec = (await pool.query('SELECT url FROM lectures WHERE id = $1', [id])).rows[0];
  if (lec && lec.url.startsWith('/uploads/')) {
    const filePath = path.join(__dirname, 'public', lec.url);
    if (fs.existsSync(filePath)) {
      try { fs.unlinkSync(filePath); } catch(e) {}
    }
  }

  await pool.query('DELETE FROM lectures WHERE id = $1', [id]);
  res.json({ ok: true });
}));

app.get('/api/admin/attendance/:lectureId', adminAuth, wrap(async (req, res) => {
  const id = Number(req.params.lectureId);
  if (!Number.isInteger(id)) return fail(res, 400, 'رقم غير صحيح.');
  const present = (
    await pool.query(
      `SELECT s.name, a.at FROM attendance a JOIN students s ON s.id = a.student_id
       WHERE a.lecture_id = $1 ORDER BY a.at`,
      [id]
    )
  ).rows;
  const absent = (
    await pool.query(
      `SELECT name FROM students
       WHERE status = 'confirmed' AND id NOT IN (SELECT student_id FROM attendance WHERE lecture_id = $1)
       ORDER BY name`,
      [id]
    )
  ).rows;
  res.json({ present, absent });
}));

app.use('/api', (req, res) => fail(res, 404, 'المسار ده مش موجود.'));
app.use((err, req, res, next) => {
  console.error(err);
  fail(res, 500, 'حصلت مشكلة في السيرفر.');
});

async function init() {
  const SCHEMA = `
    CREATE TABLE IF NOT EXISTS students (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      age INT NOT NULL,
      school TEXT NOT NULL,
      address TEXT NOT NULL,
      parent_job TEXT NOT NULL,
      parent_phone TEXT NOT NULL,
      student_phone TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      code TEXT UNIQUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS lectures (
      id SERIAL PRIMARY KEY,
      week INT DEFAULT 1,
      title TEXT NOT NULL,
      url TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS attendance (
      student_id INT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
      lecture_id INT NOT NULL REFERENCES lectures(id) ON DELETE CASCADE,
      at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (student_id, lecture_id)
    );
    ALTER TABLE students ADD COLUMN IF NOT EXISTS seq INT;
  `;
  await (pool.exec ? pool.exec(SCHEMA) : pool.query(SCHEMA));
}

const PORT = process.env.PORT || 3000;
setupDb()
  .then(init)
  .then(() => app.listen(PORT, () => console.log(`السيرفر شغال على http://localhost:${PORT}`)))
  .catch((e) => {
    console.error('فشل الاتصال بالداتا بيز:', e.message);
    process.exit(1);
  });