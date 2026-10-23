/**
 * ============================================================================
 * UniConnect — Backend API (université)
 * Node.js + Express + PostgreSQL — fichier unique
 * ============================================================================
 *
 * Auth :
 *  - Étudiants  : matricule + téléphone + OTP SMS (puis mot de passe)
 *  - Personnel  : email + mot de passe (+ OTP email si besoin)
 *
 * Modules v1 :
 *  1. Auth & comptes
 *  2. Structure académique (facultés, filières, niveaux, cours)
 *  3. Emploi du temps
 *  4. Présences (session QR dynamique)
 *  5. Notes & relevés
 *  6. Finances (frais, paiements, reçus)
 *  7. Annonces & messagerie
 *  8. Demandes de documents
 *  9. Notifications (in-app + FCM)
 * 10. Administration + audit
 *
 * Multi-langue : preferred_language sur users (fr, en, ee, ha, yo, ar, zh…)
 *
 * Démarrage :
 *   cp .env.example .env
 *   npm install
 *   node server.js
 * ============================================================================
 */

'use strict';

require('dotenv').config();

const express = require('express');
const http = require('http');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const { Pool } = require('pg');
const { Server: SocketIOServer } = require('socket.io');
const fs = require('fs');
const path = require('path');
const { parse: csvParse } = require('csv-parse/sync');
const PDFDocument = require('pdfkit');
const QRCode = require('qrcode');

// ============================================================================
// CONFIG
// ============================================================================

const PORT = process.env.PORT || 3000;
const BCRYPT_COST = 12;
const OTP_TTL_SECONDS = 5 * 60;
const ACCESS_TOKEN_EXPIRES = process.env.JWT_ACCESS_EXPIRES || '15m';
const REFRESH_TOKEN_DAYS = parseInt(process.env.JWT_REFRESH_DAYS || '30', 10);
const JWT_SECRET = process.env.JWT_ACCESS_SECRET || 'changez_moi_en_prod_uniconnect';

const ROLES = [
  'etudiant',
  'enseignant',
  'scolarite',
  'comptabilite',
  'directeur',
  'admin',
];

const SUPPORTED_LANGS = ['fr', 'en', 'ee', 'ha', 'yo', 'ar', 'zh', 'es', 'pt', 'kab'];

// ============================================================================
// EMAIL (SMTP)
// ============================================================================

let mailer = null;
try {
  if (process.env.SMTP_HOST && process.env.SMTP_USER) {
    const nodemailer = require('nodemailer');
    mailer = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587', 10),
      secure: process.env.SMTP_SECURE === 'true',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    });
    console.log('[Email] SMTP configuré.');
  }
} catch (_) {}

async function sendEmail({ to, subject, text, html }) {
  if (!mailer) {
    console.log(`[Email DEV] → ${to}\nSujet: ${subject}\n${text}`);
    return;
  }
  await mailer.sendMail({
    from: process.env.SMTP_FROM || 'UniConnect <noreply@uniconnect.edu>',
    to,
    subject,
    text,
    html: html || text,
  });
}

// ============================================================================
// SMS (Africa's Talking — optionnel)
// ============================================================================

// Caractères du jeu GSM-7 (SMS « text ») ; sinon le SMS est envoyé en Unicode.
const GSM7 = /^[A-Za-z0-9 \r\n@£$¥èéùìòÇØøÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ!"#¤%&'()*+,\-./:;<=>?¡ÄÖÑÜ§¿äöñüà^{}\\\[~\]|€]*$/;

/**
 * Envoi de SMS. Fournisseur choisi selon les variables d'environnement :
 *  1. Vonage  (VONAGE_API_KEY + VONAGE_API_SECRET [+ VONAGE_FROM])
 *  2. Africa's Talking (AT_USERNAME + AT_API_KEY)
 *  3. sinon : affichage dans les logs (développement)
 */
async function sendSms(phone, message) {
  const vKey = process.env.VONAGE_API_KEY;
  const vSecret = process.env.VONAGE_API_SECRET;
  if (vKey && vSecret) {
    try {
      const r = await axios.post(
        process.env.VONAGE_API_URL || 'https://rest.nexmo.com/sms/json',
        new URLSearchParams({
          api_key: vKey,
          api_secret: vSecret,
          to: String(phone).replace(/[^\d]/g, ''), // format international sans « + »
          from: process.env.VONAGE_FROM || 'UniConnect',
          text: message,
          type: GSM7.test(message) ? 'text' : 'unicode',
        }),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 15000 },
      );
      const m = r.data && r.data.messages && r.data.messages[0];
      if (!m || String(m.status) !== '0') {
        console.error('[SMS Vonage] Refusé :', m ? `${m.status} ${m['error-text'] || ''}` : 'réponse invalide');
      }
    } catch (e) {
      console.error('[SMS Vonage] Échec :', e.response ? JSON.stringify(e.response.data) : e.message);
    }
    return;
  }
  const username = process.env.AT_USERNAME;
  const apiKey = process.env.AT_API_KEY;
  if (!username || !apiKey) {
    console.log(`[SMS DEV] → ${phone} : ${message}`);
    return;
  }
  try {
    await axios.post(
      'https://api.africastalking.com/version1/messaging',
      new URLSearchParams({
        username,
        to: phone.startsWith('+') ? phone : `+${phone}`,
        message,
        from: process.env.AT_SENDER_ID || 'UNICONNECT',
      }),
      {
        headers: {
          apiKey,
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
        },
      },
    );
  } catch (e) {
    console.error('[SMS] Échec:', e.message);
  }
}

// ============================================================================
// REDIS / OTP
// ============================================================================

let redisClient = null;
if (process.env.REDIS_URL) {
  const Redis = require('ioredis');
  redisClient = new Redis(process.env.REDIS_URL);
  redisClient.on('error', (e) => console.error('[Redis]', e.message));
}

function generateOtp() {
  return crypto.randomInt(100000, 1000000).toString();
}

/** Année académique courante (début en septembre par défaut, ACADEMIC_YEAR_START_MONTH pour changer). */
function currentAcademicYear(date = new Date()) {
  const startMonth = parseInt(process.env.ACADEMIC_YEAR_START_MONTH || '9', 10);
  const y = date.getFullYear();
  return date.getMonth() + 1 >= startMonth ? `${y}-${y + 1}` : `${y - 1}-${y}`;
}

function normalizePhone(p) {
  return String(p || '').replace(/\s+/g, '').replace(/^\+/, '');
}

function normalizeEmail(e) {
  return String(e || '').trim().toLowerCase();
}

async function storeOtp(key, code) {
  const k = String(key).toLowerCase();
  if (redisClient) {
    await redisClient.set(`otp:${k}`, code, 'EX', OTP_TTL_SECONDS);
  } else {
    // Sans Redis : stockage PostgreSQL (survit à la mise en veille / au redémarrage du serveur)
    await pool.query(`DELETE FROM otp_codes WHERE expires_at < now()`);
    await pool.query(
      `INSERT INTO otp_codes (key, code, expires_at) VALUES ($1, $2, now() + ($3 || ' seconds')::interval)
       ON CONFLICT (key) DO UPDATE SET code = EXCLUDED.code, expires_at = EXCLUDED.expires_at`,
      [k, code, String(OTP_TTL_SECONDS)],
    );
  }
}

async function verifyAndConsumeOtp(key, code) {
  const k = String(key).toLowerCase();
  let stored = null;
  if (redisClient) {
    stored = await redisClient.get(`otp:${k}`);
    if (stored) await redisClient.del(`otp:${k}`);
  } else {
    const r = await pool.query(
      `DELETE FROM otp_codes WHERE key = $1 RETURNING code, (expires_at > now()) AS valid`, [k]);
    if (r.rows[0] && r.rows[0].valid) stored = r.rows[0].code;
  }
  return stored && stored === String(code).trim();
}

// ============================================================================
// FIREBASE PUSH
// ============================================================================

let firebaseMessaging = null;
if (
  process.env.FIREBASE_PROJECT_ID &&
  process.env.FIREBASE_CLIENT_EMAIL &&
  process.env.FIREBASE_PRIVATE_KEY
) {
  try {
    const admin = require('firebase-admin');
    let pk = process.env.FIREBASE_PRIVATE_KEY;
    if (pk.startsWith('"') && pk.endsWith('"')) pk = pk.slice(1, -1);
    pk = pk.replace(/\\n/g, '\n');
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        privateKey: pk,
      }),
    });
    firebaseMessaging = admin.messaging();
    console.log('[Firebase] Push activé.');
  } catch (e) {
    console.error('[Firebase]', e.message);
  }
}

// ============================================================================
// POSTGRESQL
// ============================================================================

const useSsl = !!process.env.DATABASE_URL || process.env.DB_SSL === 'true';
const pool = new Pool(
  process.env.DATABASE_URL
    ? {
        connectionString: process.env.DATABASE_URL,
        ssl: useSsl ? { rejectUnauthorized: false } : false,
      }
    : {
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT || '5432', 10),
        user: process.env.DB_USER || 'uniconnect',
        password: process.env.DB_PASSWORD || 'uniconnect',
        database: process.env.DB_NAME || 'uniconnect',
        ssl: useSsl ? { rejectUnauthorized: false } : false,
      },
);

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      email TEXT UNIQUE,
      phone TEXT UNIQUE,
      password_hash TEXT,
      full_name TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN (
        'etudiant','enseignant','scolarite','comptabilite','directeur','admin'
      )),
      is_active BOOLEAN DEFAULT TRUE,
      phone_verified BOOLEAN DEFAULT FALSE,
      email_verified BOOLEAN DEFAULT FALSE,
      failed_login_attempts INTEGER DEFAULT 0,
      locked_until TIMESTAMPTZ,
      preferred_language TEXT DEFAULT 'fr',
      created_at TIMESTAMPTZ DEFAULT now(),
      updated_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT UNIQUE NOT NULL,
      device_info TEXT,
      expires_at TIMESTAMPTZ NOT NULL,
      revoked BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS faculties (
      id UUID PRIMARY KEY,
      name TEXT NOT NULL,
      code TEXT UNIQUE,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS programs (
      id UUID PRIMARY KEY,
      faculty_id UUID REFERENCES faculties(id),
      name TEXT NOT NULL,
      code TEXT UNIQUE,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS levels (
      id UUID PRIMARY KEY,
      program_id UUID REFERENCES programs(id),
      name TEXT NOT NULL,
      year_order INTEGER NOT NULL DEFAULT 1,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS courses (
      id UUID PRIMARY KEY,
      program_id UUID REFERENCES programs(id),
      level_id UUID REFERENCES levels(id),
      code TEXT NOT NULL,
      title TEXT NOT NULL,
      credits NUMERIC(4,1) DEFAULT 0,
      teacher_id UUID REFERENCES users(id),
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS students (
      user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      matricule TEXT UNIQUE NOT NULL,
      program_id UUID REFERENCES programs(id),
      level_id UUID REFERENCES levels(id),
      academic_year TEXT,
      photo_url TEXT,
      group_name TEXT,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS teachers (
      user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      specialite TEXT,
      grade TEXT,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS enrollments (
      id UUID PRIMARY KEY,
      student_id UUID REFERENCES users(id) ON DELETE CASCADE,
      course_id UUID REFERENCES courses(id) ON DELETE CASCADE,
      academic_year TEXT NOT NULL,
      status TEXT DEFAULT 'inscrit' CHECK (status IN ('inscrit','abandonne','valide')),
      created_at TIMESTAMPTZ DEFAULT now(),
      UNIQUE(student_id, course_id, academic_year)
    );

    CREATE TABLE IF NOT EXISTS rooms (
      id UUID PRIMARY KEY,
      name TEXT NOT NULL,
      building TEXT,
      capacity INTEGER,
      latitude NUMERIC(9,6),
      longitude NUMERIC(9,6),
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS timetable_slots (
      id UUID PRIMARY KEY,
      course_id UUID REFERENCES courses(id) ON DELETE CASCADE,
      room_id UUID REFERENCES rooms(id),
      day_of_week INTEGER NOT NULL CHECK (day_of_week BETWEEN 0 AND 6),
      start_time TIME NOT NULL,
      end_time TIME NOT NULL,
      academic_year TEXT NOT NULL,
      semester INTEGER DEFAULT 1,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS attendance_sessions (
      id UUID PRIMARY KEY,
      course_id UUID REFERENCES courses(id),
      teacher_id UUID REFERENCES users(id),
      room_id UUID REFERENCES rooms(id),
      started_at TIMESTAMPTZ DEFAULT now(),
      expires_at TIMESTAMPTZ,
      qr_secret TEXT NOT NULL,
      status TEXT DEFAULT 'ouverte' CHECK (status IN ('ouverte','fermee')),
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS attendances (
      id UUID PRIMARY KEY,
      session_id UUID REFERENCES attendance_sessions(id) ON DELETE CASCADE,
      student_id UUID REFERENCES users(id),
      marked_at TIMESTAMPTZ DEFAULT now(),
      method TEXT DEFAULT 'qr' CHECK (method IN ('qr','manuel')),
      device_id TEXT,
      latitude NUMERIC(9,6),
      longitude NUMERIC(9,6),
      UNIQUE(session_id, student_id)
    );

    CREATE TABLE IF NOT EXISTS assignments (
      id UUID PRIMARY KEY,
      course_id UUID REFERENCES courses(id),
      teacher_id UUID REFERENCES users(id),
      title TEXT NOT NULL,
      description TEXT,
      due_at TIMESTAMPTZ,
      max_score NUMERIC(5,2) DEFAULT 20,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS submissions (
      id UUID PRIMARY KEY,
      assignment_id UUID REFERENCES assignments(id) ON DELETE CASCADE,
      student_id UUID REFERENCES users(id),
      file_url TEXT,
      content TEXT,
      submitted_at TIMESTAMPTZ DEFAULT now(),
      score NUMERIC(5,2),
      feedback TEXT,
      UNIQUE(assignment_id, student_id)
    );

    CREATE TABLE IF NOT EXISTS grades (
      id UUID PRIMARY KEY,
      student_id UUID REFERENCES users(id),
      course_id UUID REFERENCES courses(id),
      evaluation_name TEXT NOT NULL,
      score NUMERIC(5,2) NOT NULL,
      max_score NUMERIC(5,2) DEFAULT 20,
      coefficient NUMERIC(4,2) DEFAULT 1,
      academic_year TEXT,
      semester INTEGER DEFAULT 1,
      status TEXT DEFAULT 'brouillon' CHECK (status IN ('brouillon','soumis','publie')),
      published_at TIMESTAMPTZ,
      created_by UUID REFERENCES users(id),
      created_at TIMESTAMPTZ DEFAULT now(),
      updated_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS fees (
      id UUID PRIMARY KEY,
      program_id UUID REFERENCES programs(id),
      level_id UUID REFERENCES levels(id),
      academic_year TEXT NOT NULL,
      label TEXT NOT NULL,
      amount_fcfa INTEGER NOT NULL,
      due_date DATE,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS student_fees (
      id UUID PRIMARY KEY,
      student_id UUID REFERENCES users(id),
      fee_id UUID REFERENCES fees(id),
      amount_due_fcfa INTEGER NOT NULL,
      amount_paid_fcfa INTEGER DEFAULT 0,
      status TEXT DEFAULT 'impaye' CHECK (status IN ('impaye','partiel','paye')),
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS payments (
      id UUID PRIMARY KEY,
      student_id UUID REFERENCES users(id),
      student_fee_id UUID REFERENCES student_fees(id),
      amount_fcfa INTEGER NOT NULL,
      method TEXT CHECK (method IN ('mobile_money','carte','espece')),
      provider TEXT,
      reference_externe TEXT,
      status TEXT DEFAULT 'en_attente' CHECK (status IN ('en_attente','reussi','echec')),
      receipt_number TEXT UNIQUE,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS announcements (
      id UUID PRIMARY KEY,
      author_id UUID REFERENCES users(id),
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      target_role TEXT,
      faculty_id UUID,
      program_id UUID,
      level_id UUID,
      expires_at TIMESTAMPTZ,
      is_urgent BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS messages (
      id UUID PRIMARY KEY,
      sender_id UUID REFERENCES users(id),
      recipient_id UUID REFERENCES users(id),
      course_id UUID REFERENCES courses(id),
      body TEXT NOT NULL,
      read_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS document_requests (
      id UUID PRIMARY KEY,
      student_id UUID REFERENCES users(id),
      type TEXT NOT NULL CHECK (type IN (
        'attestation_scolarite','releve_notes','certificat','autre'
      )),
      status TEXT DEFAULT 'en_attente' CHECK (status IN (
        'en_attente','en_cours','pret','refuse'
      )),
      file_url TEXT,
      motif_refus TEXT,
      created_at TIMESTAMPTZ DEFAULT now(),
      updated_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      data JSONB,
      lu BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS push_tokens (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      fcm_token TEXT UNIQUE NOT NULL,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES users(id),
      action TEXT NOT NULL,
      entity_type TEXT,
      entity_id UUID,
      details JSONB,
      ip TEXT,
      created_at TIMESTAMPTZ DEFAULT now()
    );
  `);

  await migrateSchema(pool);
  await ensureStorageBucket();
  // Premier administrateur (créé une seule fois si aucun admin n'existe)
  if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
    const hasAdmin = await pool.query(`SELECT 1 FROM users WHERE role = 'admin' LIMIT 1`);
    if (!hasAdmin.rowCount) {
      await pool.query(
        `INSERT INTO users (id, full_name, email, phone, role, password_hash, phone_verified, is_active)
         VALUES ($1,$2,$3,$4,'admin',$5,$6,true)`,
        [crypto.randomUUID(), process.env.ADMIN_NAME || 'Administrateur', normalizeEmail(process.env.ADMIN_EMAIL),
          process.env.ADMIN_PHONE ? normalizePhone(process.env.ADMIN_PHONE) : null,
          await bcrypt.hash(process.env.ADMIN_PASSWORD, BCRYPT_COST), !!process.env.ADMIN_PHONE],
      );
      console.log('[DB] Compte administrateur initial créé.');
    }
  }
  // Seed minimal faculté / filière si vide
  const facCount = (await pool.query('SELECT COUNT(*) FROM faculties')).rows[0].count;
  if (Number(facCount) === 0) {
    const facId = crypto.randomUUID();
    const progId = crypto.randomUUID();
    const lvlId = crypto.randomUUID();
    await pool.query(
      `INSERT INTO faculties (id, name, code) VALUES ($1, 'Faculté des Sciences', 'FS')`,
      [facId],
    );
    await pool.query(
      `INSERT INTO programs (id, faculty_id, name, code) VALUES ($1, $2, 'Informatique', 'INFO')`,
      [progId, facId],
    );
    await pool.query(
      `INSERT INTO levels (id, program_id, name, year_order) VALUES ($1, $2, 'L1', 1)`,
      [lvlId, progId],
    );
    console.log('[DB] Seed faculté / filière / niveau L1 créé.');
  }

  console.log('[DB] Tables UniConnect prêtes.');
}

// ============================================================================
// HELPERS
// ============================================================================

function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

function hashToken(t) {
  return crypto.createHash('sha256').update(t).digest('hex');
}

function signAccessToken(user) {
  return jwt.sign(
    { sub: user.id, role: user.role, name: user.full_name },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_EXPIRES },
  );
}

async function createRefreshToken(userId, deviceInfo) {
  const raw = crypto.randomBytes(48).toString('hex');
  const id = crypto.randomUUID();
  const expires = new Date();
  expires.setDate(expires.getDate() + REFRESH_TOKEN_DAYS);
  await pool.query(
    `INSERT INTO refresh_tokens (id, user_id, token_hash, device_info, expires_at)
     VALUES ($1,$2,$3,$4,$5)`,
    [id, userId, hashToken(raw), deviceInfo || null, expires],
  );
  return raw;
}

function serializeUser(u) {
  return {
    id: u.id,
    email: u.email,
    phone: u.phone,
    fullName: u.full_name,
    role: u.role,
    isActive: u.is_active,
    preferredLanguage: u.preferred_language || 'fr',
    createdAt: u.created_at,
  };
}

async function audit(userId, action, entityType, entityId, details, ip) {
  try {
    await pool.query(
      `INSERT INTO audit_logs (id, user_id, action, entity_type, entity_id, details, ip)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [crypto.randomUUID(), userId, action, entityType || null, entityId || null, details || null, ip || null],
    );
  } catch (_) {}
}

// Traductions notifications (multi-langue)
const NOTIF_I18N = {
  grade_published: {
    fr: { title: 'Notes publiées', body: 'Vos notes de {course} sont disponibles.' },
    en: { title: 'Grades published', body: 'Your grades for {course} are available.' },
  },
  timetable_change: {
    fr: { title: 'Emploi du temps modifié', body: 'Changement pour {course} : {detail}' },
    en: { title: 'Timetable updated', body: 'Change for {course}: {detail}' },
  },
  payment_success: {
    fr: { title: 'Paiement confirmé', body: 'Paiement de {amount} FCFA reçu. Reçu n°{receipt}' },
    en: { title: 'Payment confirmed', body: 'Payment of {amount} FCFA received. Receipt #{receipt}' },
  },
  announcement: {
    fr: { title: '{title}', body: '{body}' },
    en: { title: '{title}', body: '{body}' },
  },
  document_ready: {
    fr: { title: 'Document prêt', body: 'Votre demande ({type}) est prête à télécharger.' },
    en: { title: 'Document ready', body: 'Your request ({type}) is ready to download.' },
  },
  attendance_alert: {
    fr: { title: 'Assiduité', body: 'Attention : absences élevées en {course}.' },
    en: { title: 'Attendance', body: 'Warning: high absences in {course}.' },
  },
};

function tNotif(type, lang, vars = {}) {
  const entry = NOTIF_I18N[type] || {};
  const pack = entry[lang] || entry.fr || { title: type, body: '' };
  let title = pack.title || type;
  let body = pack.body || '';
  for (const [k, v] of Object.entries(vars)) {
    title = title.replace(new RegExp(`\\{${k}\\}`, 'g'), String(v));
    body = body.replace(new RegExp(`\\{${k}\\}`, 'g'), String(v));
  }
  return { title, body };
}

async function notifyUser(userId, type, vars = {}, data = {}) {
  const u = (await pool.query('SELECT preferred_language FROM users WHERE id = $1', [userId])).rows[0];
  const lang = (u && u.preferred_language) || 'fr';
  const { title, body } = tNotif(type, lang, vars);

  await pool.query(
    `INSERT INTO notifications (id, user_id, type, title, message, data)
     VALUES ($1,$2,$3,$4,$5,$6)`,
    [crypto.randomUUID(), userId, type, title, body, data],
  );

  if (firebaseMessaging) {
    try {
      const tokens = (
        await pool.query('SELECT fcm_token FROM push_tokens WHERE user_id = $1', [userId])
      ).rows.map((r) => r.fcm_token);
      if (tokens.length) {
        await firebaseMessaging.sendEachForMulticast({
          tokens,
          notification: { title, body },
          data: { type, ...Object.fromEntries(Object.entries(data).map(([k, v]) => [k, String(v)])) },
          android: { priority: 'high' },
        });
      }
    } catch (e) {
      console.error('[Push]', e.message);
    }
  }
}

// ============================================================================
// MIDDLEWARE
// ============================================================================

const app = express();
app.use(helmet());
app.set('trust proxy', 1);
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '2mb', verify: (req, _res, buf) => { req.rawBody = buf; } }));
app.use(express.urlencoded({ extended: true }));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: parseInt(process.env.AUTH_RATE_LIMIT || '40', 10), standardHeaders: true });
const generalLimiter = rateLimit({ windowMs: 60 * 1000, max: parseInt(process.env.GENERAL_RATE_LIMIT || '120', 10) });

app.use('/api/', generalLimiter);

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'Token manquant.' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = { id: payload.sub, role: payload.role, name: payload.name };
    next();
  } catch {
    return res.status(401).json({ message: 'Token invalide ou expiré.' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Accès refusé pour ce rôle.' });
    }
    next();
  };
}

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 8 * 1024 * 1024 } });

// ============================================================================
// ROUTES
// ============================================================================

const router = express.Router();

// ---------- AUTH ----------

/** Étudiant : première activation (ou réinitialisation) — matricule + téléphone → OTP SMS */
const otpCooldown = new Map();
const STAFF_2FA_ROLES = ['scolarite', 'comptabilite', 'directeur', 'admin'];
// Défis 2FA du personnel : table login_challenges (persistante)
const deviceName = (req) => req.headers['x-device-name'] || req.headers['user-agent'];

router.post(
  '/auth/student/request-otp',
  authLimiter,
  asyncHandler(async (req, res) => {
    const { matricule, phone } = req.body;
    if (!matricule || !phone) {
      return res.status(400).json({ message: 'matricule et téléphone requis.' });
    }
    const st = (
      await pool.query(
        `SELECT s.user_id, u.phone, u.password_hash, u.is_active
         FROM students s JOIN users u ON u.id = s.user_id
         WHERE s.matricule = $1`,
        [String(matricule).trim().toUpperCase()],
      )
    ).rows[0];
    if (!st) return res.status(404).json({ message: 'Matricule inconnu. Contactez la scolarité.' });
    if (!st.is_active) return res.status(403).json({ message: 'Compte désactivé.' });

    const norm = normalizePhone(phone);
    const stored = st.phone ? normalizePhone(st.phone) : null;
    if (stored && stored !== norm) {
      // Un tiers connaissant le matricule ne peut pas rattacher son propre numéro.
      return res.status(403).json({
        message: 'Ce numéro ne correspond pas à celui enregistré pour ce matricule. Contactez la scolarité.',
      });
    }
    if (!stored) {
      if (st.password_hash) {
        return res.status(403).json({ message: 'Compte déjà activé : contactez la scolarité.' });
      }
      const taken = await pool.query('SELECT 1 FROM users WHERE phone = $1 AND id <> $2', [norm, st.user_id]);
      if (taken.rowCount) return res.status(409).json({ message: 'Ce numéro est déjà utilisé.' });
      await pool.query('UPDATE users SET phone = $1, updated_at = now() WHERE id = $2', [norm, st.user_id]);
    }
    const last = otpCooldown.get(norm) || 0;
    if (Date.now() - last < 60 * 1000) {
      return res.status(429).json({ message: 'Patientez une minute avant de redemander un code.' });
    }
    otpCooldown.set(norm, Date.now());

    const code = generateOtp();
    await storeOtp(`phone:${norm}`, code);
    await sendSms(norm, `UniConnect : votre code est ${code} (valide 5 min).`);
    res.json({ message: 'Code OTP envoyé par SMS.', phone: norm.replace(/(\d{3})\d+(\d{2})/, '$1****$2') });
  }),
);

/** Vérifier OTP + définir mot de passe (activation) */
router.post(
  '/auth/student/verify-otp',
  authLimiter,
  asyncHandler(async (req, res) => {
    const { phone, code, password } = req.body;
    if (!phone || !code) return res.status(400).json({ message: 'phone et code requis.' });
    const norm = normalizePhone(phone);
    const u = (await pool.query('SELECT * FROM users WHERE phone = $1 AND is_active', [norm])).rows[0];
    if (!u) return res.status(404).json({ message: 'Utilisateur introuvable.' });
    if (!u.password_hash && (!password || password.length < 8)) {
      return res.status(400).json({ message: 'Choisissez un mot de passe (8 caractères minimum).' });
    }
    if (password && password.length < 8) {
      return res.status(400).json({ message: 'Mot de passe : 8 caractères minimum.' });
    }
    const ok = await verifyAndConsumeOtp(`phone:${norm}`, code);
    if (!ok) return res.status(400).json({ message: 'Code OTP invalide ou expiré.' });

    if (password) {
      const hash = await bcrypt.hash(password, BCRYPT_COST);
      await pool.query(
        `UPDATE users SET password_hash = $1, phone_verified = true, failed_login_attempts = 0, locked_until = NULL, updated_at = now() WHERE id = $2`,
        [hash, u.id],
      );
      await pool.query('UPDATE refresh_tokens SET revoked = true WHERE user_id = $1', [u.id]);
    } else {
      await pool.query(`UPDATE users SET phone_verified = true, updated_at = now() WHERE id = $1`, [u.id]);
    }
    const accessToken = signAccessToken(u);
    const refreshToken = await createRefreshToken(u.id, deviceName(req));
    res.json({ accessToken, refreshToken, user: serializeUser({ ...u, phone_verified: true }) });
  }),
);

/** Login classique (e-mail, téléphone ou matricule + mot de passe). Le personnel passe par une 2e étape OTP. */
router.post(
  '/auth/login',
  authLimiter,
  asyncHandler(async (req, res) => {
    const { email, phone, matricule, password } = req.body;
    if (!password) return res.status(400).json({ message: 'Mot de passe requis.' });

    let u = null;
    if (email) {
      u = (await pool.query('SELECT * FROM users WHERE email = $1', [normalizeEmail(email)])).rows[0];
    } else if (phone) {
      u = (await pool.query('SELECT * FROM users WHERE phone = $1', [normalizePhone(phone)])).rows[0];
    } else if (matricule) {
      u = (
        await pool.query(
          `SELECT u.* FROM users u JOIN students s ON s.user_id = u.id WHERE s.matricule = $1`,
          [String(matricule).trim().toUpperCase()],
        )
      ).rows[0];
    } else {
      return res.status(400).json({ message: 'email, phone ou matricule requis.' });
    }

    if (!u || !u.is_active) return res.status(401).json({ message: 'Identifiants incorrects.' });
    if (u.locked_until && new Date(u.locked_until) > new Date()) {
      return res.status(423).json({ message: 'Compte temporairement verrouillé.' });
    }
    if (!u.password_hash) {
      return res.status(400).json({ message: "Activez d'abord votre compte (OTP)." });
    }

    const match = await bcrypt.compare(password, u.password_hash);
    if (!match) {
      const attempts = (u.failed_login_attempts || 0) + 1;
      const locked = attempts >= 5 ? new Date(Date.now() + 15 * 60 * 1000) : null;
      await pool.query(
        `UPDATE users SET failed_login_attempts = $1, locked_until = $2 WHERE id = $3`,
        [attempts, locked, u.id],
      );
      if (locked) {
        const msg = 'UniConnect : 5 tentatives de connexion échouées, compte verrouillé 15 minutes.';
        if (u.phone) sendSms(u.phone, msg).catch(() => {});
        else if (u.email) sendEmail({ to: u.email, subject: 'Compte verrouillé', text: msg }).catch(() => {});
      }
      return res.status(401).json({ message: 'Identifiants incorrects.' });
    }

    await pool.query(
      `UPDATE users SET failed_login_attempts = 0, locked_until = NULL, updated_at = now() WHERE id = $1`,
      [u.id],
    );

    // Authentification à deux facteurs pour les rôles sensibles
    if (STAFF_2FA_ROLES.includes(u.role) && process.env.STAFF_2FA !== 'false') {
      if (!u.phone && !u.email) {
        return res.status(400).json({ message: 'Aucun téléphone ni e-mail pour envoyer le code : contactez un administrateur.' });
      }
      const challengeId = crypto.randomUUID();
      const code = generateOtp();
      await pool.query(`DELETE FROM login_challenges WHERE expires_at < now()`);
      await pool.query(
        `INSERT INTO login_challenges (id, user_id, code, expires_at) VALUES ($1, $2, $3, now() + ($4 || ' seconds')::interval)`,
        [challengeId, u.id, code, String(OTP_TTL_SECONDS)],
      );
      const msg = `UniConnect : code de connexion ${code} (valide 5 min).`;
      if (u.phone) await sendSms(u.phone, msg);
      else await sendEmail({ to: u.email, subject: 'Code de connexion', text: msg });
      return res.json({ requiresOtp: true, challengeId, channel: u.phone ? 'sms' : 'email' });
    }

    const accessToken = signAccessToken(u);
    const refreshToken = await createRefreshToken(u.id, deviceName(req));
    res.json({ accessToken, refreshToken, user: serializeUser(u) });
  }),
);

router.post(
  '/auth/refresh',
  asyncHandler(async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ message: 'refreshToken requis.' });
    const hash = hashToken(refreshToken);
    const row = (
      await pool.query(
        `SELECT rt.id AS rt_id, u.id, u.role, u.full_name, u.is_active
         FROM refresh_tokens rt JOIN users u ON u.id = rt.user_id
         WHERE rt.token_hash = $1 AND rt.revoked = false AND rt.expires_at > now()`,
        [hash],
      )
    ).rows[0];
    if (!row || !row.is_active) return res.status(401).json({ message: 'Refresh token invalide.' });

    // Rotation atomique : un refresh token ne sert qu'une fois
    const rev = await pool.query(
      'UPDATE refresh_tokens SET revoked = true WHERE id = $1 AND revoked = false RETURNING id',
      [row.rt_id],
    );
    if (!rev.rowCount) return res.status(401).json({ message: 'Refresh token déjà utilisé.' });
    const accessToken = signAccessToken(row);
    const newRefresh = await createRefreshToken(row.id, deviceName(req));
    res.json({ accessToken, refreshToken: newRefresh });
  }),
);

router.get(
  '/auth/me',
  requireAuth,
  asyncHandler(async (req, res) => {
    const u = (await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id])).rows[0];
    if (!u) return res.status(404).json({ message: 'Utilisateur introuvable.' });
    const out = serializeUser(u);
    if (u.role === 'etudiant') {
      const st = (await pool.query('SELECT * FROM students WHERE user_id = $1', [u.id])).rows[0];
      if (st) {
        out.matricule = st.matricule;
        out.programId = st.program_id;
        out.levelId = st.level_id;
        out.academicYear = st.academic_year;
        out.photoUrl = st.photo_url;
      }
    }
    res.json(out);
  }),
);

router.patch(
  '/users/me',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { preferredLanguage, fullName } = req.body;
    const sets = [];
    const vals = [];
    let i = 1;
    if (preferredLanguage && SUPPORTED_LANGS.includes(preferredLanguage)) {
      sets.push(`preferred_language = $${i++}`);
      vals.push(preferredLanguage);
    }
    if (fullName) {
      sets.push(`full_name = $${i++}`);
      vals.push(fullName);
    }
    if (!sets.length) return res.status(400).json({ message: 'Rien à mettre à jour.' });
    sets.push('updated_at = now()');
    vals.push(req.user.id);
    await pool.query(`UPDATE users SET ${sets.join(', ')} WHERE id = $${i}`, vals);
    res.json({ message: 'Profil mis à jour.' });
  }),
);

// ---------- ÉTUDIANT ----------

router.get(
  '/students/me',
  requireAuth,
  requireRole('etudiant'),
  asyncHandler(async (req, res) => {
    const st = (
      await pool.query(
        `SELECT s.*, p.name as program_name, l.name as level_name, f.name as faculty_name
         FROM students s
         LEFT JOIN programs p ON p.id = s.program_id
         LEFT JOIN levels l ON l.id = s.level_id
         LEFT JOIN faculties f ON f.id = p.faculty_id
         WHERE s.user_id = $1`,
        [req.user.id],
      )
    ).rows[0];
    if (!st) return res.status(404).json({ message: 'Profil étudiant introuvable.' });
    res.json({
      matricule: st.matricule,
      programName: st.program_name,
      levelName: st.level_name,
      facultyName: st.faculty_name,
      academicYear: st.academic_year,
      photoUrl: st.photo_url,
      groupName: st.group_name,
    });
  }),
);

// ---------- EMPLOI DU TEMPS : voir modules/academic.js ----------

// ---------- NOTES, PRÉSENCES, FINANCES, ANNONCES, DOCUMENTS : voir modules/ ----------

// ---------- NOTIFICATIONS ----------

router.post(
  '/notifications/register-token',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { fcmToken } = req.body;
    if (!fcmToken) return res.status(400).json({ message: 'fcmToken requis.' });
    await pool.query(`DELETE FROM push_tokens WHERE user_id = $1 OR fcm_token = $2`, [
      req.user.id,
      fcmToken,
    ]);
    await pool.query(`INSERT INTO push_tokens (id, user_id, fcm_token) VALUES ($1,$2,$3)`, [
      crypto.randomUUID(),
      req.user.id,
      fcmToken,
    ]);
    res.status(204).send();
  }),
);

router.get(
  '/notifications',
  requireAuth,
  asyncHandler(async (req, res) => {
    const rows = (
      await pool.query(
        `SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50`,
        [req.user.id],
      )
    ).rows;
    res.json(
      rows.map((n) => ({
        id: n.id,
        type: n.type,
        title: n.title,
        message: n.message,
        lu: n.lu,
        data: n.data,
        createdAt: n.created_at,
      })),
    );
  }),
);

router.patch(
  '/notifications/:id/read',
  requireAuth,
  asyncHandler(async (req, res) => {
    await pool.query(`UPDATE notifications SET lu = true WHERE id = $1 AND user_id = $2`, [
      req.params.id,
      req.user.id,
    ]);
    res.json({ message: 'OK' });
  }),
);

// ---------- ADMIN ----------

router.get(
  '/admin/users',
  requireAuth,
  requireRole('admin', 'scolarite'),
  asyncHandler(async (req, res) => {
    const rows = (
      await pool.query(`SELECT * FROM users ORDER BY created_at DESC LIMIT 200`)
    ).rows;
    res.json(rows.map(serializeUser));
  }),
);

router.post(
  '/admin/students',
  requireAuth,
  requireRole('admin', 'scolarite'),
  asyncHandler(async (req, res) => {
    const { fullName, matricule, phone, email, programId, levelId, academicYear, groupName } = req.body;
    if (!fullName || !matricule) {
      return res.status(400).json({ message: 'fullName et matricule requis.' });
    }
    const userId = crypto.randomUUID();
    await pool.query(
      `INSERT INTO users (id, full_name, phone, email, role, is_active)
       VALUES ($1,$2,$3,$4,'etudiant',true)`,
      [userId, fullName, phone ? normalizePhone(phone) : null, email ? normalizeEmail(email) : null],
    );
    await pool.query(
      `INSERT INTO students (user_id, matricule, program_id, level_id, academic_year, group_name)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [userId, String(matricule).trim().toUpperCase(), programId || null, levelId || null, academicYear || currentAcademicYear(), groupName || null],
    );
    await app.locals.syncStudent(userId);
    await audit(req.user.id, 'create_student', 'user', userId, { matricule }, req.ip);
    res.status(201).json({ userId, matricule, message: 'Étudiant créé. Il pourra activer son compte via OTP.' });
  }),
);

router.patch(
  '/admin/users/:id/deactivate',
  requireAuth,
  requireRole('admin'),
  asyncHandler(async (req, res) => {
    await pool.query(`UPDATE users SET is_active = false WHERE id = $1`, [req.params.id]);
    await pool.query('UPDATE refresh_tokens SET revoked = true WHERE user_id = $1', [req.params.id]);
    await audit(req.user.id, 'deactivate_user', 'user', req.params.id, null, req.ip);
    res.json({ message: 'Compte désactivé.' });
  }),
);

router.patch(
  '/admin/users/:id/reactivate',
  requireAuth,
  requireRole('admin'),
  asyncHandler(async (req, res) => {
    await pool.query(`UPDATE users SET is_active = true WHERE id = $1`, [req.params.id]);
    res.json({ message: 'Compte réactivé.' });
  }),
);

router.get(
  '/admin/dashboard',
  requireAuth,
  requireRole('admin', 'directeur', 'scolarite'),
  asyncHandler(async (req, res) => {
    const totalStudents = Number(
      (await pool.query(`SELECT COUNT(*) FROM users WHERE role = 'etudiant' AND is_active = true`)).rows[0]
        .count,
    );
    const totalTeachers = Number(
      (await pool.query(`SELECT COUNT(*) FROM users WHERE role = 'enseignant' AND is_active = true`)).rows[0]
        .count,
    );
    const pendingDocs = Number(
      (await pool.query(`SELECT COUNT(*) FROM document_requests WHERE status = 'en_attente'`)).rows[0]
        .count,
    );
    const unpaid = Number(
      (await pool.query(`SELECT COUNT(*) FROM student_fees WHERE status != 'paye'`)).rows[0].count,
    );
    res.json({ totalStudents, totalTeachers, pendingDocs, unpaidFees: unpaid });
  }),
);

// Structure académique (lecture)
router.get(
  '/faculties',
  requireAuth,
  asyncHandler(async (req, res) => {
    const rows = (await pool.query(`SELECT * FROM faculties ORDER BY name`)).rows;
    res.json(rows);
  }),
);

router.get(
  '/programs',
  requireAuth,
  asyncHandler(async (req, res) => {
    const q = req.query.facultyId
      ? await pool.query(`SELECT * FROM programs WHERE faculty_id = $1 ORDER BY name`, [req.query.facultyId])
      : await pool.query(`SELECT * FROM programs ORDER BY name`);
    res.json(q.rows);
  }),
);

// ============================================================================
// MODULES COMPLÉMENTAIRES (cahier des charges complet) — regroupés dans ce fichier
// ============================================================================

/** Tables et colonnes complémentaires (idempotent). */
async function migrateSchema(pool) {
  await pool.query(`
    CREATE SEQUENCE IF NOT EXISTS receipt_seq;
    CREATE SEQUENCE IF NOT EXISTS matricule_seq START 1000;

    ALTER TABLE students ADD COLUMN IF NOT EXISTS birth_date DATE;
    ALTER TABLE students ADD COLUMN IF NOT EXISTS device_id TEXT;
    ALTER TABLE courses  ADD COLUMN IF NOT EXISTS semester INTEGER DEFAULT 1;
    ALTER TABLE courses  ADD COLUMN IF NOT EXISTS is_optional BOOLEAN DEFAULT FALSE;
    ALTER TABLE courses  ADD COLUMN IF NOT EXISTS prerequisite_course_id UUID;
    ALTER TABLE levels   ADD COLUMN IF NOT EXISTS total_credits INTEGER DEFAULT 60;
    ALTER TABLE levels   ADD COLUMN IF NOT EXISTS max_credits INTEGER DEFAULT 66;
    ALTER TABLE announcements ADD COLUMN IF NOT EXISTS course_id UUID;
    ALTER TABLE announcements ADD COLUMN IF NOT EXISTS group_name TEXT;
    ALTER TABLE announcements ADD COLUMN IF NOT EXISTS send_sms BOOLEAN DEFAULT FALSE;
    ALTER TABLE messages ADD COLUMN IF NOT EXISTS hidden BOOLEAN DEFAULT FALSE;
    ALTER TABLE payments ADD COLUMN IF NOT EXISTS paid_at TIMESTAMPTZ;
    ALTER TABLE payments ADD COLUMN IF NOT EXISTS recorded_by UUID;
    ALTER TABLE payments ADD COLUMN IF NOT EXISTS note TEXT;
    ALTER TABLE attendance_sessions ADD COLUMN IF NOT EXISTS closed_at TIMESTAMPTZ;
    ALTER TABLE timetable_slots ADD COLUMN IF NOT EXISTS group_name TEXT;
    ALTER TABLE document_requests ADD COLUMN IF NOT EXISTS issued_code TEXT;
    ALTER TABLE document_requests ADD COLUMN IF NOT EXISTS academic_year TEXT;
    ALTER TABLE submissions ADD COLUMN IF NOT EXISTS file_id UUID;

    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);

    CREATE TABLE IF NOT EXISTS otp_codes (
      key TEXT PRIMARY KEY, code TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE IF NOT EXISTS login_challenges (
      id UUID PRIMARY KEY, user_id UUID NOT NULL, code TEXT NOT NULL,
      tries INTEGER NOT NULL DEFAULT 0, expires_at TIMESTAMPTZ NOT NULL
    );

    CREATE TABLE IF NOT EXISTS files (
      id UUID PRIMARY KEY, owner_id UUID, original_name TEXT, mime TEXT,
      size INTEGER, path TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS issued_documents (
      id UUID PRIMARY KEY, code TEXT UNIQUE NOT NULL, type TEXT NOT NULL,
      student_id UUID REFERENCES users(id), academic_year TEXT, payload JSONB,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS grade_history (
      id UUID PRIMARY KEY, grade_id UUID REFERENCES grades(id) ON DELETE CASCADE,
      old_score NUMERIC(5,2), new_score NUMERIC(5,2), motif TEXT NOT NULL,
      changed_by UUID REFERENCES users(id), created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS grade_claims (
      id UUID PRIMARY KEY, grade_id UUID REFERENCES grades(id) ON DELETE CASCADE,
      student_id UUID REFERENCES users(id), motif TEXT NOT NULL,
      status TEXT DEFAULT 'en_attente' CHECK (status IN ('en_attente','acceptee','rejetee')),
      response TEXT, handled_by UUID REFERENCES users(id),
      created_at TIMESTAMPTZ DEFAULT now(), handled_at TIMESTAMPTZ,
      UNIQUE(grade_id, student_id)
    );

    CREATE TABLE IF NOT EXISTS course_materials (
      id UUID PRIMARY KEY, course_id UUID REFERENCES courses(id) ON DELETE CASCADE,
      teacher_id UUID REFERENCES users(id), title TEXT NOT NULL,
      file_id UUID, link TEXT, created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS applications (
      id UUID PRIMARY KEY, code TEXT UNIQUE NOT NULL, full_name TEXT NOT NULL,
      phone TEXT NOT NULL, email TEXT, birth_date DATE,
      program_id UUID REFERENCES programs(id), level_id UUID REFERENCES levels(id),
      status TEXT DEFAULT 'recu' CHECK (status IN ('recu','en_examen','pieces_manquantes','accepte','refuse')),
      note TEXT, student_user_id UUID, created_at TIMESTAMPTZ DEFAULT now(),
      updated_at TIMESTAMPTZ DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS application_documents (
      id UUID PRIMARY KEY, application_id UUID REFERENCES applications(id) ON DELETE CASCADE,
      doc_type TEXT NOT NULL, file_id UUID, created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS reenrollment_requests (
      id UUID PRIMARY KEY, student_id UUID REFERENCES users(id),
      academic_year TEXT NOT NULL, level_id UUID REFERENCES levels(id),
      course_ids UUID[] NOT NULL, status TEXT DEFAULT 'en_attente'
        CHECK (status IN ('en_attente','valide','refuse')),
      note TEXT, created_at TIMESTAMPTZ DEFAULT now(), handled_at TIMESTAMPTZ,
      UNIQUE(student_id, academic_year)
    );

    CREATE TABLE IF NOT EXISTS absence_justifications (
      id UUID PRIMARY KEY, session_id UUID REFERENCES attendance_sessions(id) ON DELETE CASCADE,
      student_id UUID REFERENCES users(id), reason TEXT NOT NULL, file_id UUID,
      status TEXT DEFAULT 'en_attente' CHECK (status IN ('en_attente','acceptee','rejetee')),
      created_at TIMESTAMPTZ DEFAULT now(), UNIQUE(session_id, student_id)
    );
    CREATE TABLE IF NOT EXISTS attendance_alerts_sent (
      student_id UUID, course_id UUID, academic_year TEXT, PRIMARY KEY(student_id, course_id, academic_year)
    );
    CREATE TABLE IF NOT EXISTS reminders_sent (
      student_fee_id UUID, kind TEXT, day DATE, PRIMARY KEY(student_fee_id, kind, day)
    );

    CREATE TABLE IF NOT EXISTS library_items (
      id UUID PRIMARY KEY, title TEXT NOT NULL, author TEXT, isbn TEXT, category TEXT,
      copies_total INTEGER DEFAULT 1, copies_available INTEGER DEFAULT 1,
      created_at TIMESTAMPTZ DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS library_reservations (
      id UUID PRIMARY KEY, item_id UUID REFERENCES library_items(id) ON DELETE CASCADE,
      user_id UUID REFERENCES users(id), status TEXT DEFAULT 'active' CHECK (status IN ('active','honoree','annulee')),
      created_at TIMESTAMPTZ DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS library_loans (
      id UUID PRIMARY KEY, item_id UUID REFERENCES library_items(id) ON DELETE CASCADE,
      user_id UUID REFERENCES users(id), borrowed_at TIMESTAMPTZ DEFAULT now(),
      due_at TIMESTAMPTZ NOT NULL, returned_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS exams (
      id UUID PRIMARY KEY, course_id UUID REFERENCES courses(id) ON DELETE CASCADE,
      academic_year TEXT NOT NULL, semester INTEGER DEFAULT 1, kind TEXT DEFAULT 'examen',
      exam_date DATE NOT NULL, start_time TIME NOT NULL, duration_minutes INTEGER DEFAULT 120,
      created_at TIMESTAMPTZ DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS exam_seats (
      exam_id UUID REFERENCES exams(id) ON DELETE CASCADE, student_id UUID REFERENCES users(id),
      room_id UUID REFERENCES rooms(id), seat_number INTEGER, PRIMARY KEY(exam_id, student_id)
    );

    CREATE TABLE IF NOT EXISTS internships (
      id UUID PRIMARY KEY, title TEXT NOT NULL, company TEXT NOT NULL, description TEXT,
      location TEXT, deadline DATE, status TEXT DEFAULT 'en_attente'
        CHECK (status IN ('en_attente','publie','refuse')),
      posted_by UUID REFERENCES users(id), created_at TIMESTAMPTZ DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS internship_applications (
      internship_id UUID REFERENCES internships(id) ON DELETE CASCADE,
      student_id UUID REFERENCES users(id), message TEXT,
      created_at TIMESTAMPTZ DEFAULT now(), PRIMARY KEY(internship_id, student_id)
    );

    CREATE TABLE IF NOT EXISTS message_reports (
      id UUID PRIMARY KEY, message_id UUID REFERENCES messages(id) ON DELETE CASCADE,
      reporter_id UUID REFERENCES users(id), reason TEXT, created_at TIMESTAMPTZ DEFAULT now(),
      UNIQUE(message_id, reporter_id)
    );

    CREATE INDEX IF NOT EXISTS idx_grades_student ON grades(student_id, status);
    CREATE INDEX IF NOT EXISTS idx_enroll_course ON enrollments(course_id, academic_year);
    CREATE INDEX IF NOT EXISTS idx_attend_session ON attendances(session_id);
    CREATE INDEX IF NOT EXISTS idx_msg_course ON messages(course_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);
  `);
  // Sécurité Supabase : verrouille l'accès direct (clé anon / API Data) à toutes les tables.
  // Le backend se connecte avec le rôle propriétaire (postgres), qui contourne ces règles.
  try {
    await pool.query(`
      DO $$ DECLARE r record; BEGIN
        FOR r IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP
          EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', r.tablename);
        END LOOP;
      END $$;`);
  } catch (e) { console.warn('[DB] RLS non appliquée :', e.message); }
}

// ============================== MODULE : academic ==============================
const mod_academic = (d, C) => {
  const { router, app, pool, crypto, bcrypt, requireAuth, requireRole, asyncHandler, audit,
    notifyUser, upload, sendSms, sendEmail, normalizePhone, normalizeEmail, currentAcademicYear,
    BCRYPT_COST } = d;
  const ADM = requireRole('admin', 'scolarite');
  const STAFF = requireRole(...C.STAFF);
  const DAYS = ['Dimanche', 'Lundi', 'Mardi', 'Mercredi', 'Jeudi', 'Vendredi', 'Samedi'];
  const tempPassword = () => crypto.randomBytes(6).toString('base64url');

  // ---------- Synchronisation d'un étudiant : cours obligatoires + frais ----------
  async function syncStudent(userId) {
    const st = (await pool.query('SELECT * FROM students WHERE user_id=$1', [userId])).rows[0];
    if (!st) return;
    const year = st.academic_year || currentAcademicYear();
    if (st.level_id) {
      await pool.query(
        `INSERT INTO enrollments (id, student_id, course_id, academic_year)
         SELECT gen_random_uuid(), $1, c.id, $2 FROM courses c
         WHERE c.level_id=$3 AND COALESCE(c.is_optional,false)=false
         ON CONFLICT DO NOTHING`,
        [userId, year, st.level_id],
      );
    }
    await pool.query(
      `INSERT INTO student_fees (id, student_id, fee_id, amount_due_fcfa)
       SELECT gen_random_uuid(), $1, f.id, f.amount_fcfa FROM fees f
       WHERE f.academic_year=$2 AND (f.program_id IS NULL OR f.program_id=$3)
         AND (f.level_id IS NULL OR f.level_id=$4)
         AND NOT EXISTS (SELECT 1 FROM student_fees x WHERE x.student_id=$1 AND x.fee_id=f.id)`,
      [userId, year, st.program_id, st.level_id],
    );
  }
  app.locals.syncStudent = syncStudent;
  C.syncStudent = syncStudent;

  // ---------- CRUD générique de la structure académique ----------
  function crud(name, table, fields, listSql, required) {
    router.get(`/admin/${name}`, requireAuth, STAFF, asyncHandler(async (req, res) => {
      res.json((await pool.query(listSql)).rows);
    }));
    router.post(`/admin/${name}`, requireAuth, ADM, asyncHandler(async (req, res) => {
      for (const f of required) if (req.body[f] == null || req.body[f] === '') throw C.err(400, `Champ requis : ${f}`);
      const cols = fields.filter((f) => req.body[f] !== undefined);
      const id = crypto.randomUUID();
      await pool.query(
        `INSERT INTO ${table} (id, ${cols.join(',')}) VALUES ($1, ${cols.map((_, i) => `$${i + 2}`).join(',')})`,
        [id, ...cols.map((c) => (req.body[c] === '' ? null : req.body[c]))],
      );
      await audit(req.user.id, `create_${name}`, name, id, req.body, req.ip);
      res.status(201).json({ id });
    }));
    router.patch(`/admin/${name}/:id`, requireAuth, ADM, asyncHandler(async (req, res) => {
      const cols = fields.filter((f) => req.body[f] !== undefined);
      if (!cols.length) throw C.err(400, 'Rien à modifier.');
      await pool.query(
        `UPDATE ${table} SET ${cols.map((c, i) => `${c}=$${i + 2}`).join(',')} WHERE id=$1`,
        [req.params.id, ...cols.map((c) => (req.body[c] === '' ? null : req.body[c]))],
      );
      await audit(req.user.id, `update_${name}`, name, req.params.id, req.body, req.ip);
      res.json({ message: 'Modifié.' });
    }));
    router.delete(`/admin/${name}/:id`, requireAuth, requireRole('admin'), asyncHandler(async (req, res) => {
      await pool.query(`DELETE FROM ${table} WHERE id=$1`, [req.params.id]);
      await audit(req.user.id, `delete_${name}`, name, req.params.id, null, req.ip);
      res.json({ message: 'Supprimé.' });
    }));
  }
  crud('faculties', 'faculties', ['name', 'code'], 'SELECT * FROM faculties ORDER BY name', ['name']);
  crud('programs', 'programs', ['faculty_id', 'name', 'code'],
    'SELECT p.*, f.name AS faculty_name FROM programs p LEFT JOIN faculties f ON f.id=p.faculty_id ORDER BY p.name', ['name']);
  crud('levels', 'levels', ['program_id', 'name', 'year_order', 'total_credits', 'max_credits'],
    'SELECT l.*, p.name AS program_name FROM levels l LEFT JOIN programs p ON p.id=l.program_id ORDER BY p.name, l.year_order', ['name', 'program_id']);
  crud('courses', 'courses',
    ['program_id', 'level_id', 'code', 'title', 'credits', 'teacher_id', 'semester', 'is_optional', 'prerequisite_course_id'],
    `SELECT c.*, u.full_name AS teacher_name, l.name AS level_name, p.name AS program_name
     FROM courses c LEFT JOIN users u ON u.id=c.teacher_id LEFT JOIN levels l ON l.id=c.level_id
     LEFT JOIN programs p ON p.id=c.program_id ORDER BY c.code`, ['code', 'title']);
  crud('rooms', 'rooms', ['name', 'building', 'capacity', 'latitude', 'longitude'],
    'SELECT * FROM rooms ORDER BY building, name', ['name']);

  // Lecture authentifiée de la structure pour les formulaires
  router.get('/levels', requireAuth, asyncHandler(async (req, res) => {
    res.json((await pool.query('SELECT l.*, p.name AS program_name FROM levels l LEFT JOIN programs p ON p.id=l.program_id ORDER BY p.name, l.year_order')).rows);
  }));
  router.get('/rooms', requireAuth, asyncHandler(async (req, res) => {
    res.json((await pool.query('SELECT * FROM rooms ORDER BY building, name')).rows);
  }));

  // ---------- Cours visibles selon le rôle ----------
  router.get('/courses', requireAuth, asyncHandler(async (req, res) => {
    const base = `SELECT c.*, u.full_name AS teacher_name FROM courses c LEFT JOIN users u ON u.id=c.teacher_id`;
    let rows;
    if (req.user.role === 'enseignant') {
      rows = (await pool.query(`${base} WHERE c.teacher_id=$1 ORDER BY c.code`, [req.user.id])).rows;
    } else if (req.user.role === 'etudiant') {
      const ids = await C.studentCourseIds(req.user.id, req.query.academicYear || currentAcademicYear());
      rows = (await pool.query(`${base} WHERE c.id = ANY($1) ORDER BY c.code`, [ids])).rows;
    } else {
      rows = (await pool.query(`${base} ORDER BY c.code`)).rows;
    }
    res.json(rows);
  }));
  router.get('/courses/:id/students', requireAuth, asyncHandler(async (req, res) => {
    await C.ownCourse(req.params.id, req.user);
    res.json(await C.roster(req.params.id, req.query.academicYear || currentAcademicYear()));
  }));

  // ---------- Emploi du temps ----------
  async function conflicts(slot, excludeId) {
    const course = (await pool.query('SELECT * FROM courses WHERE id=$1', [slot.courseId])).rows[0];
    if (!course) throw C.err(404, 'Cours introuvable.');
    const base = `SELECT ts.id, c.code, ts.start_time, ts.end_time FROM timetable_slots ts
      JOIN courses c ON c.id=ts.course_id
      WHERE ts.day_of_week=$1 AND ts.academic_year=$2 AND ts.start_time < $4::time AND ts.end_time > $3::time
        AND ts.id <> COALESCE($5::uuid, '00000000-0000-0000-0000-000000000000'::uuid)`;
    const p = [slot.dayOfWeek, slot.academicYear, slot.startTime, slot.endTime, excludeId || null];
    const out = [];
    if (slot.roomId) {
      const r = await pool.query(`${base} AND ts.room_id=$6`, [...p, slot.roomId]);
      r.rows.forEach((x) => out.push(`Salle déjà occupée par ${x.code} (${x.start_time}-${x.end_time})`));
    }
    if (course.teacher_id) {
      const r = await pool.query(`${base} AND c.teacher_id=$6`, [...p, course.teacher_id]);
      r.rows.forEach((x) => out.push(`Enseignant déjà pris par ${x.code} (${x.start_time}-${x.end_time})`));
    }
    if (course.level_id) {
      const r = await pool.query(
        `${base} AND c.level_id=$6 AND c.id<>$7 AND (COALESCE(ts.group_name,'')='' OR COALESCE($8::text,'')='' OR ts.group_name=$8::text)`,
        [...p, course.level_id, course.id, slot.groupName || null]);
      r.rows.forEach((x) => out.push(`Le niveau a déjà ${x.code} (${x.start_time}-${x.end_time})`));
    }
    return { course, list: out };
  }
  async function notifyCourse(courseId, detail) {
    const c = (await pool.query('SELECT title, teacher_id FROM courses WHERE id=$1', [courseId])).rows[0];
    const ids = new Set((await C.roster(courseId, currentAcademicYear())).map((r) => r.id));
    if (c && c.teacher_id) ids.add(c.teacher_id);
    for (const id of ids) {
      await notifyUser(id, 'timetable_change', { course: c ? c.title : '', detail }, { courseId }).catch(() => {});
    }
  }
  const slotFrom = (b, old = {}) => ({
    courseId: b.courseId ?? old.course_id, roomId: b.roomId !== undefined ? b.roomId || null : old.room_id,
    dayOfWeek: Number(b.dayOfWeek ?? old.day_of_week), startTime: b.startTime ?? old.start_time,
    endTime: b.endTime ?? old.end_time, academicYear: b.academicYear ?? old.academic_year ?? currentAcademicYear(),
    semester: b.semester ?? old.semester ?? 1, groupName: b.groupName !== undefined ? b.groupName || null : old.group_name,
  });
  const roomName = async (id) => (id ? (await pool.query('SELECT name FROM rooms WHERE id=$1', [id])).rows[0]?.name : null);

  router.get('/admin/timetable', requireAuth, STAFF, asyncHandler(async (req, res) => {
    const year = req.query.academicYear || currentAcademicYear();
    res.json((await pool.query(
      `SELECT ts.*, c.code AS course_code, c.title AS course_title, r.name AS room_name, u.full_name AS teacher_name
       FROM timetable_slots ts JOIN courses c ON c.id=ts.course_id LEFT JOIN rooms r ON r.id=ts.room_id
       LEFT JOIN users u ON u.id=c.teacher_id WHERE ts.academic_year=$1
       ORDER BY ts.day_of_week, ts.start_time`, [year])).rows);
  }));
  router.post('/admin/timetable', requireAuth, ADM, asyncHandler(async (req, res) => {
    const s = slotFrom(req.body);
    if (!s.courseId || Number.isNaN(s.dayOfWeek) || !s.startTime || !s.endTime) throw C.err(400, 'Cours, jour, début et fin requis.');
    if (s.startTime >= s.endTime) throw C.err(400, "L'heure de fin doit suivre l'heure de début.");
    const { list } = await conflicts(s);
    if (list.length) return res.status(409).json({ message: "Conflit d'horaire.", conflicts: list });
    const id = crypto.randomUUID();
    await pool.query(
      `INSERT INTO timetable_slots (id, course_id, room_id, day_of_week, start_time, end_time, academic_year, semester, group_name)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [id, s.courseId, s.roomId, s.dayOfWeek, s.startTime, s.endTime, s.academicYear, s.semester, s.groupName]);
    const room = await roomName(s.roomId);
    await notifyCourse(s.courseId, `nouveau créneau ${DAYS[s.dayOfWeek]} ${s.startTime}-${s.endTime}${room ? ', salle ' + room : ''}`);
    await audit(req.user.id, 'create_slot', 'timetable_slot', id, s, req.ip);
    res.status(201).json({ id });
  }));
  router.patch('/admin/timetable/:id', requireAuth, ADM, asyncHandler(async (req, res) => {
    const old = (await pool.query('SELECT * FROM timetable_slots WHERE id=$1', [req.params.id])).rows[0];
    if (!old) throw C.err(404, 'Créneau introuvable.');
    const s = slotFrom(req.body, old);
    const { list } = await conflicts(s, old.id);
    if (list.length) return res.status(409).json({ message: "Conflit d'horaire.", conflicts: list });
    await pool.query(
      `UPDATE timetable_slots SET course_id=$2, room_id=$3, day_of_week=$4, start_time=$5, end_time=$6,
       academic_year=$7, semester=$8, group_name=$9 WHERE id=$1`,
      [old.id, s.courseId, s.roomId, s.dayOfWeek, s.startTime, s.endTime, s.academicYear, s.semester, s.groupName]);
    const room = await roomName(s.roomId);
    await notifyCourse(s.courseId, `${DAYS[s.dayOfWeek]} ${s.startTime}-${s.endTime}${room ? ', salle ' + room : ''}`);
    await audit(req.user.id, 'update_slot', 'timetable_slot', old.id, req.body, req.ip);
    res.json({ message: 'Créneau modifié, étudiants notifiés.' });
  }));
  router.delete('/admin/timetable/:id', requireAuth, ADM, asyncHandler(async (req, res) => {
    const old = (await pool.query('DELETE FROM timetable_slots WHERE id=$1 RETURNING *', [req.params.id])).rows[0];
    if (old) await notifyCourse(old.course_id, `créneau du ${DAYS[old.day_of_week]} ${old.start_time} supprimé`);
    await audit(req.user.id, 'delete_slot', 'timetable_slot', req.params.id, null, req.ip);
    res.json({ message: 'Supprimé.' });
  }));
  /** Annulation d'une séance précise (notification immédiate). */
  router.post('/admin/timetable/:id/cancel', requireAuth, requireRole('admin', 'scolarite', 'enseignant'), asyncHandler(async (req, res) => {
    const slot = (await pool.query('SELECT * FROM timetable_slots WHERE id=$1', [req.params.id])).rows[0];
    if (!slot) throw C.err(404, 'Créneau introuvable.');
    if (req.user.role === 'enseignant') await C.ownCourse(slot.course_id, req.user);
    await notifyCourse(slot.course_id, `séance du ${req.body.date || DAYS[slot.day_of_week]} annulée${req.body.reason ? ' : ' + req.body.reason : ''}`);
    res.json({ message: 'Séance annulée, étudiants notifiés.' });
  }));

  router.get('/timetable/me', requireAuth, asyncHandler(async (req, res) => {
    const year = req.query.academicYear || currentAcademicYear();
    let ids = [];
    let group = null;
    if (req.user.role === 'etudiant') {
      ids = await C.studentCourseIds(req.user.id, year);
      group = (await pool.query('SELECT group_name FROM students WHERE user_id=$1', [req.user.id])).rows[0]?.group_name || null;
    } else if (req.user.role === 'enseignant') {
      ids = (await pool.query('SELECT id FROM courses WHERE teacher_id=$1', [req.user.id])).rows.map((r) => r.id);
    }
    if (!ids.length) return res.json([]);
    const rows = (await pool.query(
      `SELECT ts.*, c.code AS course_code, c.title AS course_title, r.name AS room_name, r.building, u.full_name AS teacher_name
       FROM timetable_slots ts JOIN courses c ON c.id=ts.course_id LEFT JOIN rooms r ON r.id=ts.room_id
       LEFT JOIN users u ON u.id=c.teacher_id
       WHERE ts.course_id = ANY($1) AND ts.academic_year=$2 ORDER BY ts.day_of_week, ts.start_time`, [ids, year])).rows;
    res.json(rows.filter((s) => !s.group_name || !group || s.group_name === group || req.user.role === 'enseignant').map((s) => ({
      id: s.id, courseId: s.course_id, courseCode: s.course_code, courseTitle: s.course_title,
      dayOfWeek: s.day_of_week, startTime: s.start_time, endTime: s.end_time, roomName: s.room_name,
      building: s.building, semester: s.semester, groupName: s.group_name, teacherName: s.teacher_name,
    })));
  }));

  // ---------- Étudiants : liste, fiche, modification, import ----------
  router.get('/admin/students', requireAuth, STAFF, asyncHandler(async (req, res) => {
    const p = [];
    let w = 'WHERE 1=1';
    if (req.query.q) { p.push(`%${req.query.q}%`); w += ` AND (u.full_name ILIKE $${p.length} OR s.matricule ILIKE $${p.length})`; }
    if (req.query.programId) { p.push(req.query.programId); w += ` AND s.program_id=$${p.length}`; }
    if (req.query.levelId) { p.push(req.query.levelId); w += ` AND s.level_id=$${p.length}`; }
    const limit = Math.min(Number(req.query.limit) || 100, 500);
    const rows = (await pool.query(
      `SELECT u.id, u.full_name, u.phone, u.email, u.is_active, u.phone_verified, s.matricule, s.group_name,
              s.academic_year, p.name AS program_name, l.name AS level_name, s.program_id, s.level_id
       FROM students s JOIN users u ON u.id=s.user_id LEFT JOIN programs p ON p.id=s.program_id
       LEFT JOIN levels l ON l.id=s.level_id ${w} ORDER BY u.full_name LIMIT ${limit}`, p)).rows;
    res.json(rows);
  }));
  router.get('/admin/students/:id', requireAuth, STAFF, asyncHandler(async (req, res) => {
    const id = req.params.id;
    const profile = (await pool.query(
      `SELECT u.id, u.full_name, u.phone, u.email, u.is_active, s.matricule, s.group_name, s.academic_year, s.program_id, s.level_id,
              p.name AS program_name, l.name AS level_name
       FROM users u JOIN students s ON s.user_id=u.id LEFT JOIN programs p ON p.id=s.program_id
       LEFT JOIN levels l ON l.id=s.level_id WHERE u.id=$1`, [id])).rows[0];
    if (!profile) throw C.err(404, 'Étudiant introuvable.');
    const fees = (await pool.query(
      `SELECT sf.*, f.label, f.due_date FROM student_fees sf JOIN fees f ON f.id=sf.fee_id WHERE sf.student_id=$1`, [id])).rows;
    res.json({ profile, fees, summary: await C.computeSummary(id) });
  }));
  router.patch('/admin/students/:id', requireAuth, ADM, asyncHandler(async (req, res) => {
    const b = req.body;
    await pool.query(
      `UPDATE students SET program_id=COALESCE($2,program_id), level_id=COALESCE($3,level_id),
       group_name=COALESCE($4,group_name), academic_year=COALESCE($5,academic_year),
       matricule=COALESCE($6,matricule) WHERE user_id=$1`,
      [req.params.id, b.programId || null, b.levelId || null, b.groupName ?? null, b.academicYear || null,
        b.matricule ? String(b.matricule).trim().toUpperCase() : null]);
    await syncStudent(req.params.id);
    await audit(req.user.id, 'update_student', 'user', req.params.id, b, req.ip);
    res.json({ message: 'Étudiant mis à jour.' });
  }));

  router.post('/admin/students/import', requireAuth, ADM, upload.single('file'), asyncHandler(async (req, res) => {
    if (!req.file) throw C.err(400, 'Fichier CSV requis (champ "file").');
    let records;
    try {
      records = csvParse(req.file.buffer, { columns: true, bom: true, trim: true, skip_empty_lines: true, delimiter: [',', ';'] });
    } catch (e) { throw C.err(400, 'CSV illisible : ' + e.message); }
    const year = currentAcademicYear();
    const created = []; const errors = [];
    let line = 1;
    for (const r of records) {
      line += 1;
      try {
        const fullName = r.fullName || r.nom || r.full_name;
        const matricule = String(r.matricule || '').trim().toUpperCase();
        if (!fullName || !matricule) throw new Error('fullName et matricule requis');
        const prog = r.programCode ? (await pool.query('SELECT id FROM programs WHERE code=$1', [r.programCode])).rows[0] : null;
        if (r.programCode && !prog) throw new Error(`filière inconnue (${r.programCode})`);
        const lvl = prog && r.levelName ? (await pool.query('SELECT id FROM levels WHERE program_id=$1 AND name=$2', [prog.id, r.levelName])).rows[0] : null;
        if (r.levelName && !lvl) throw new Error(`niveau inconnu (${r.levelName})`);
        const uid = crypto.randomUUID();
        const phone = r.phone ? normalizePhone(r.phone) : null;
        await pool.query(`INSERT INTO users (id, full_name, phone, email, role) VALUES ($1,$2,$3,$4,'etudiant')`,
          [uid, fullName, phone, r.email ? normalizeEmail(r.email) : null]);
        await pool.query(`INSERT INTO students (user_id, matricule, program_id, level_id, academic_year, group_name)
          VALUES ($1,$2,$3,$4,$5,$6)`, [uid, matricule, prog?.id || null, lvl?.id || null, r.academicYear || year, r.groupName || null]);
        await syncStudent(uid);
        created.push(matricule);
      } catch (e) {
        errors.push({ line, message: e.code === '23505' ? 'matricule, téléphone ou e-mail déjà utilisé' : e.message });
      }
    }
    await audit(req.user.id, 'import_students', 'user', null, { created: created.length, errors: errors.length }, req.ip);
    res.json({ created: created.length, errors });
  }));

  // ---------- Enseignants, personnel, mots de passe ----------
  async function createAccount(body, role) {
    const { fullName, email, phone } = body;
    if (!fullName || (!email && !phone)) throw C.err(400, 'Nom et e-mail ou téléphone requis.');
    const id = crypto.randomUUID();
    const pwd = tempPassword();
    await pool.query(
      `INSERT INTO users (id, full_name, email, phone, role, password_hash, phone_verified) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [id, fullName, email ? normalizeEmail(email) : null, phone ? normalizePhone(phone) : null, role,
        await bcrypt.hash(pwd, BCRYPT_COST), !!phone]);
    const msg = `UniConnect : compte créé. Identifiant : ${email || phone}. Mot de passe temporaire : ${pwd}`;
    if (phone) await sendSms(normalizePhone(phone), msg);
    if (email) await sendEmail({ to: normalizeEmail(email), subject: 'Votre compte UniConnect', text: msg });
    return { id, tempPassword: pwd };
  }
  router.post('/admin/teachers', requireAuth, ADM, asyncHandler(async (req, res) => {
    const acc = await createAccount(req.body, 'enseignant');
    await pool.query('INSERT INTO teachers (user_id, specialite, grade) VALUES ($1,$2,$3)',
      [acc.id, req.body.specialite || null, req.body.grade || null]);
    await audit(req.user.id, 'create_teacher', 'user', acc.id, null, req.ip);
    res.status(201).json(acc);
  }));
  router.get('/admin/teachers', requireAuth, STAFF, asyncHandler(async (req, res) => {
    res.json((await pool.query(
      `SELECT u.id, u.full_name, u.email, u.phone, u.is_active, t.specialite, t.grade
       FROM users u LEFT JOIN teachers t ON t.user_id=u.id WHERE u.role='enseignant' ORDER BY u.full_name`)).rows);
  }));
  router.post('/admin/staff', requireAuth, requireRole('admin'), asyncHandler(async (req, res) => {
    const role = req.body.role;
    if (!['scolarite', 'comptabilite', 'directeur', 'admin'].includes(role)) throw C.err(400, 'Rôle invalide.');
    const acc = await createAccount(req.body, role);
    await audit(req.user.id, 'create_staff', 'user', acc.id, { role }, req.ip);
    res.status(201).json(acc);
  }));
  router.patch('/admin/users/:id', requireAuth, ADM, asyncHandler(async (req, res) => {
    const b = req.body;
    if (b.role && req.user.role !== 'admin') throw C.err(403, 'Seul un administrateur change les rôles.');
    await pool.query(
      `UPDATE users SET full_name=COALESCE($2,full_name), phone=COALESCE($3,phone), email=COALESCE($4,email),
       role=COALESCE($5,role), updated_at=now() WHERE id=$1`,
      [req.params.id, b.fullName || null, b.phone ? normalizePhone(b.phone) : null, b.email ? normalizeEmail(b.email) : null, b.role || null]);
    await audit(req.user.id, 'update_user', 'user', req.params.id, b, req.ip);
    res.json({ message: 'Utilisateur mis à jour.' });
  }));
  router.post('/admin/users/:id/reset-password', requireAuth, ADM, asyncHandler(async (req, res) => {
    const u = (await pool.query('SELECT * FROM users WHERE id=$1', [req.params.id])).rows[0];
    if (!u) throw C.err(404, 'Utilisateur introuvable.');
    const pwd = tempPassword();
    await pool.query('UPDATE users SET password_hash=$2, failed_login_attempts=0, locked_until=NULL WHERE id=$1', [u.id, await bcrypt.hash(pwd, BCRYPT_COST)]);
    await pool.query('UPDATE refresh_tokens SET revoked=true WHERE user_id=$1', [u.id]);
    const msg = `UniConnect : nouveau mot de passe temporaire : ${pwd}`;
    if (u.phone) await sendSms(u.phone, msg);
    if (u.email) await sendEmail({ to: u.email, subject: 'Mot de passe UniConnect', text: msg });
    await audit(req.user.id, 'reset_password', 'user', u.id, null, req.ip);
    res.json({ message: 'Mot de passe réinitialisé et envoyé.', tempPassword: pwd });
  }));

  // ---------- Inscriptions aux cours ----------
  router.post('/admin/enrollments', requireAuth, ADM, asyncHandler(async (req, res) => {
    const { studentId, courseId, academicYear } = req.body;
    if (!studentId || !courseId) throw C.err(400, 'studentId et courseId requis.');
    await pool.query(
      `INSERT INTO enrollments (id, student_id, course_id, academic_year) VALUES ($1,$2,$3,$4)
       ON CONFLICT (student_id, course_id, academic_year) DO UPDATE SET status='inscrit'`,
      [crypto.randomUUID(), studentId, courseId, academicYear || currentAcademicYear()]);
    res.status(201).json({ message: 'Inscrit au cours.' });
  }));
  router.delete('/admin/enrollments', requireAuth, ADM, asyncHandler(async (req, res) => {
    await pool.query(`UPDATE enrollments SET status='abandonne' WHERE student_id=$1 AND course_id=$2 AND academic_year=$3`,
      [req.body.studentId, req.body.courseId, req.body.academicYear || currentAcademicYear()]);
    res.json({ message: 'Désinscrit.' });
  }));

  // ---------- Paramètres de l'établissement ----------
  const SETTING_KEYS = ['institution_name', 'block_if_unpaid', 'absence_threshold', 'claim_window_days',
    'pass_credit_ratio', 'loan_days', 'geofence_meters'];
  router.get('/admin/settings', requireAuth, STAFF, asyncHandler(async (req, res) => {
    const out = {};
    for (const r of (await pool.query('SELECT * FROM settings')).rows) out[r.key] = r.value;
    res.json(out);
  }));
  router.put('/admin/settings', requireAuth, requireRole('admin', 'scolarite'), asyncHandler(async (req, res) => {
    for (const [k, v] of Object.entries(req.body || {})) {
      if (!SETTING_KEYS.includes(k)) continue;
      await pool.query('INSERT INTO settings (key,value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=$2', [k, String(v)]);
    }
    await audit(req.user.id, 'update_settings', 'settings', null, req.body, req.ip);
    res.json({ message: 'Paramètres enregistrés.' });
  }));

  // ---------- Téléchargement sécurisé des fichiers ----------
  router.post('/files', requireAuth, upload.single('file'), asyncHandler(async (req, res) => {
    if (!req.file) throw C.err(400, 'Fichier manquant.');
    const id = await C.saveFile(req.file, req.user.id);
    res.status(201).json({ id, url: C.fileUrl(id) });
  }));
  router.get('/files/:id', requireAuth, asyncHandler(async (req, res) => {
    const f = (await pool.query('SELECT * FROM files WHERE id=$1', [req.params.id])).rows[0];
    if (!f) throw C.err(404, 'Fichier introuvable.');
    let ok = f.owner_id === req.user.id || req.user.role !== 'etudiant';
    if (!ok) {
      const ids = await C.studentCourseIds(req.user.id, currentAcademicYear());
      ok = (await pool.query('SELECT 1 FROM course_materials WHERE file_id=$1 AND course_id = ANY($2)', [f.id, ids])).rowCount > 0;
    }
    if (!ok) throw C.err(403, 'Accès refusé.');
    res.setHeader('Content-Type', f.mime || 'application/octet-stream');
    res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(f.original_name || 'fichier')}"`);
    res.send(await C.storeGet(f.path));
  }));
};

// ============================== MODULE : auth-extra ==============================
const mod_auth_extra = (d, C) => {
  const { router, app, pool, bcrypt, requireAuth, asyncHandler, audit, authLimiter, upload,
    sendSms, sendEmail, generateOtp, storeOtp, verifyAndConsumeOtp, normalizePhone, normalizeEmail,
    signAccessToken, createRefreshToken, serializeUser, hashToken, BCRYPT_COST } = d;
  const validPwd = (p) => typeof p === 'string' && p.length >= 8;

  /** 2e étape de connexion du personnel (scolarité, comptabilité, direction, admin). */
  router.post('/auth/login/verify-otp', authLimiter, asyncHandler(async (req, res) => {
    const { challengeId, code } = req.body;
    const chr = await pool.query(
      `UPDATE login_challenges SET tries = tries + 1 WHERE id = $1 AND expires_at > now() RETURNING user_id, code, tries`, [challengeId]);
    const ch = chr.rows[0];
    if (!ch) throw C.err(400, 'Code expiré, reconnectez-vous.');
    if (ch.tries > 5) { await pool.query('DELETE FROM login_challenges WHERE id = $1', [challengeId]); throw C.err(429, 'Trop de tentatives.'); }
    if (String(code).trim() !== ch.code) throw C.err(400, 'Code incorrect.');
    await pool.query('DELETE FROM login_challenges WHERE id = $1', [challengeId]);
    const u = (await pool.query('SELECT * FROM users WHERE id=$1 AND is_active', [ch.user_id])).rows[0];
    if (!u) throw C.err(401, 'Compte indisponible.');
    await audit(u.id, 'login_staff', 'user', u.id, null, req.ip);
    res.json({
      accessToken: signAccessToken(u),
      refreshToken: await createRefreshToken(u.id, req.headers['x-device-name'] || req.headers['user-agent']),
      user: serializeUser(u),
    });
  }));

  // ---------- Mot de passe oublié ----------
  async function findByIdentifier(id) {
    const s = String(id || '').trim();
    if (!s) return null;
    const r = await pool.query(
      `SELECT u.* FROM users u LEFT JOIN students st ON st.user_id=u.id
       WHERE u.email=$1 OR u.phone=$2 OR st.matricule=$3 LIMIT 1`,
      [normalizeEmail(s), normalizePhone(s), s.toUpperCase()]);
    return r.rows[0] || null;
  }
  router.post('/auth/forgot-password', authLimiter, asyncHandler(async (req, res) => {
    const u = await findByIdentifier(req.body.identifier);
    if (u && u.is_active) {
      const code = generateOtp();
      await storeOtp(`reset:${u.id}`, code);
      const msg = `UniConnect : code de réinitialisation ${code} (valide 5 min).`;
      if (u.phone) await sendSms(u.phone, msg);
      else if (u.email) await sendEmail({ to: u.email, subject: 'Réinitialisation du mot de passe', text: msg });
    }
    res.json({ message: 'Si le compte existe, un code a été envoyé.' });
  }));
  router.post('/auth/reset-password', authLimiter, asyncHandler(async (req, res) => {
    const { identifier, code, newPassword } = req.body;
    if (!validPwd(newPassword)) throw C.err(400, 'Mot de passe : 8 caractères minimum.');
    const u = await findByIdentifier(identifier);
    if (!u || !(await verifyAndConsumeOtp(`reset:${u.id}`, code))) throw C.err(400, 'Code invalide ou expiré.');
    await pool.query(
      `UPDATE users SET password_hash=$2, failed_login_attempts=0, locked_until=NULL, updated_at=now() WHERE id=$1`,
      [u.id, await bcrypt.hash(newPassword, BCRYPT_COST)]);
    await pool.query('UPDATE refresh_tokens SET revoked=true WHERE user_id=$1', [u.id]);
    await audit(u.id, 'reset_password_self', 'user', u.id, null, req.ip);
    res.json({ message: 'Mot de passe modifié. Reconnectez-vous.' });
  }));
  router.post('/auth/change-password', requireAuth, asyncHandler(async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    if (!validPwd(newPassword)) throw C.err(400, 'Mot de passe : 8 caractères minimum.');
    const u = (await pool.query('SELECT * FROM users WHERE id=$1', [req.user.id])).rows[0];
    if (!u.password_hash || !(await bcrypt.compare(oldPassword || '', u.password_hash))) throw C.err(400, 'Ancien mot de passe incorrect.');
    await pool.query('UPDATE users SET password_hash=$2, updated_at=now() WHERE id=$1', [u.id, await bcrypt.hash(newPassword, BCRYPT_COST)]);
    res.json({ message: 'Mot de passe modifié.' });
  }));

  // ---------- Appareils connectés ----------
  router.get('/auth/sessions', requireAuth, asyncHandler(async (req, res) => {
    const rows = (await pool.query(
      `SELECT id, device_info, created_at, expires_at FROM refresh_tokens
       WHERE user_id=$1 AND revoked=false AND expires_at>now() ORDER BY created_at DESC`, [req.user.id])).rows;
    res.json(rows.map((r) => ({ id: r.id, device: r.device_info, createdAt: r.created_at, expiresAt: r.expires_at })));
  }));
  router.delete('/auth/sessions/:id', requireAuth, asyncHandler(async (req, res) => {
    await pool.query('UPDATE refresh_tokens SET revoked=true WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    res.json({ message: 'Session fermée.' });
  }));
  router.post('/auth/logout', requireAuth, asyncHandler(async (req, res) => {
    if (req.body.refreshToken) {
      await pool.query('UPDATE refresh_tokens SET revoked=true WHERE token_hash=$1 AND user_id=$2',
        [hashToken(req.body.refreshToken), req.user.id]);
    }
    res.json({ message: 'Déconnecté.' });
  }));
  router.post('/auth/logout-all', requireAuth, asyncHandler(async (req, res) => {
    await pool.query('UPDATE refresh_tokens SET revoked=true WHERE user_id=$1', [req.user.id]);
    res.json({ message: 'Tous les appareils déconnectés.' });
  }));

  // ---------- Photo de profil ----------
  router.post('/users/me/photo', requireAuth, upload.single('photo'), asyncHandler(async (req, res) => {
    if (!req.file || !/^image\//.test(req.file.mimetype)) throw C.err(400, 'Image requise.');
    const id = await C.saveFile(req.file, req.user.id);
    await pool.query('UPDATE students SET photo_url=$2 WHERE user_id=$1', [req.user.id, C.fileUrl(id)]);
    res.json({ url: C.fileUrl(id) });
  }));
};

// ============================== MODULE : learning ==============================
const mod_learning = (d, C) => {
  const { router, pool, crypto, requireAuth, requireRole, asyncHandler, notifyUser, upload,
    currentAcademicYear } = d;
  const TEACH = requireRole('enseignant', 'scolarite', 'admin');
  const year = (req) => req.query.academicYear || currentAcademicYear();

  async function notifyStudents(courseId, type, vars, data) {
    for (const s of await C.roster(courseId, currentAcademicYear())) {
      await notifyUser(s.id, type, vars, data).catch(() => {});
    }
  }

  // ---------- Supports de cours ----------
  router.get('/courses/:id/materials', requireAuth, asyncHandler(async (req, res) => {
    if (req.user.role === 'etudiant' && !(await C.studentInCourse(req.user.id, req.params.id, year(req)))) {
      throw C.err(403, 'Vous ne suivez pas ce cours.');
    }
    if (req.user.role === 'enseignant') await C.ownCourse(req.params.id, req.user);
    const rows = (await pool.query(
      `SELECT m.*, f.original_name, f.mime FROM course_materials m LEFT JOIN files f ON f.id=m.file_id
       WHERE m.course_id=$1 ORDER BY m.created_at DESC`, [req.params.id])).rows;
    res.json(rows.map((m) => ({
      id: m.id, title: m.title, link: m.link, fileUrl: C.fileUrl(m.file_id),
      fileName: m.original_name, mime: m.mime, createdAt: m.created_at,
    })));
  }));
  router.post('/courses/:id/materials', requireAuth, TEACH, upload.single('file'), asyncHandler(async (req, res) => {
    const course = await C.ownCourse(req.params.id, req.user);
    const { title, link } = req.body;
    if (!title || (!req.file && !link)) throw C.err(400, 'Titre et fichier ou lien requis.');
    const fileId = await C.saveFile(req.file, req.user.id);
    const id = crypto.randomUUID();
    await pool.query(
      'INSERT INTO course_materials (id, course_id, teacher_id, title, file_id, link) VALUES ($1,$2,$3,$4,$5,$6)',
      [id, course.id, req.user.id, title, fileId, link || null]);
    await notifyStudents(course.id, 'material_new', { course: course.title, title }, { courseId: course.id });
    res.status(201).json({ id });
  }));
  router.delete('/materials/:id', requireAuth, TEACH, asyncHandler(async (req, res) => {
    const m = (await pool.query('SELECT * FROM course_materials WHERE id=$1', [req.params.id])).rows[0];
    if (!m) throw C.err(404, 'Support introuvable.');
    await C.ownCourse(m.course_id, req.user);
    await pool.query('DELETE FROM course_materials WHERE id=$1', [m.id]);
    res.json({ message: 'Supprimé.' });
  }));

  // ---------- Devoirs ----------
  router.post('/courses/:id/assignments', requireAuth, TEACH, asyncHandler(async (req, res) => {
    const course = await C.ownCourse(req.params.id, req.user);
    const { title, description, dueAt, maxScore } = req.body;
    if (!title || !dueAt) throw C.err(400, 'Titre et date limite requis.');
    const id = crypto.randomUUID();
    await pool.query(
      'INSERT INTO assignments (id, course_id, teacher_id, title, description, due_at, max_score) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [id, course.id, req.user.id, title, description || null, dueAt, maxScore || 20]);
    await notifyStudents(course.id, 'assignment_new',
      { course: course.title, title, date: new Date(dueAt).toLocaleDateString('fr-FR') }, { assignmentId: id });
    res.status(201).json({ id });
  }));
  router.get('/courses/:id/assignments', requireAuth, TEACH, asyncHandler(async (req, res) => {
    await C.ownCourse(req.params.id, req.user);
    res.json((await pool.query(
      `SELECT a.*, (SELECT COUNT(*) FROM submissions s WHERE s.assignment_id=a.id) AS submissions
       FROM assignments a WHERE a.course_id=$1 ORDER BY a.due_at DESC`, [req.params.id])).rows);
  }));
  /** Devoirs de l'étudiant avec l'état de son rendu. */
  router.get('/assignments/me', requireAuth, requireRole('etudiant'), asyncHandler(async (req, res) => {
    const ids = await C.studentCourseIds(req.user.id, currentAcademicYear());
    const rows = (await pool.query(
      `SELECT a.*, c.code, c.title AS course_title, s.id AS submission_id, s.submitted_at, s.score, s.feedback, s.file_url
       FROM assignments a JOIN courses c ON c.id=a.course_id
       LEFT JOIN submissions s ON s.assignment_id=a.id AND s.student_id=$1
       WHERE a.course_id = ANY($2) ORDER BY a.due_at DESC`, [req.user.id, ids])).rows;
    res.json(rows.map((a) => ({
      id: a.id, courseCode: a.code, courseTitle: a.course_title, title: a.title, description: a.description,
      dueAt: a.due_at, maxScore: Number(a.max_score), late: new Date(a.due_at) < new Date(),
      submitted: !!a.submission_id, submittedAt: a.submitted_at, score: a.score == null ? null : Number(a.score),
      feedback: a.feedback, fileUrl: a.file_url,
    })));
  }));
  /** Dépôt (ou remplacement avant la date limite) avec accusé de réception horodaté. */
  router.post('/assignments/:id/submit', requireAuth, requireRole('etudiant'), upload.single('file'), asyncHandler(async (req, res) => {
    const a = (await pool.query('SELECT * FROM assignments WHERE id=$1', [req.params.id])).rows[0];
    if (!a) throw C.err(404, 'Devoir introuvable.');
    if (!(await C.studentInCourse(req.user.id, a.course_id, currentAcademicYear()))) throw C.err(403, 'Vous ne suivez pas ce cours.');
    if (new Date(a.due_at) < new Date()) throw C.err(400, 'La date limite est dépassée.');
    if (!req.file && !req.body.content) throw C.err(400, 'Fichier ou texte requis.');
    const fileId = await C.saveFile(req.file, req.user.id);
    const r = (await pool.query(
      `INSERT INTO submissions (id, assignment_id, student_id, file_id, file_url, content)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT (assignment_id, student_id) DO UPDATE SET file_id=COALESCE($4, submissions.file_id),
         file_url=COALESCE($5, submissions.file_url), content=COALESCE($6, submissions.content), submitted_at=now()
       RETURNING id, submitted_at`,
      [crypto.randomUUID(), a.id, req.user.id, fileId, C.fileUrl(fileId), req.body.content || null])).rows[0];
    res.status(201).json({ id: r.id, receivedAt: r.submitted_at, message: 'Devoir bien reçu.' });
  }));
  router.get('/assignments/:id/submissions', requireAuth, TEACH, asyncHandler(async (req, res) => {
    const a = (await pool.query('SELECT * FROM assignments WHERE id=$1', [req.params.id])).rows[0];
    if (!a) throw C.err(404, 'Devoir introuvable.');
    await C.ownCourse(a.course_id, req.user);
    const roster = await C.roster(a.course_id, currentAcademicYear());
    const subs = (await pool.query('SELECT * FROM submissions WHERE assignment_id=$1', [a.id])).rows;
    const by = new Map(subs.map((s) => [s.student_id, s]));
    res.json(roster.map((st) => {
      const s = by.get(st.id);
      return {
        studentId: st.id, studentName: st.full_name, matricule: st.matricule, submissionId: s?.id || null,
        submittedAt: s?.submitted_at || null, fileUrl: s?.file_url || null, content: s?.content || null,
        score: s?.score == null ? null : Number(s.score), feedback: s?.feedback || null,
      };
    }));
  }));
  router.patch('/submissions/:id', requireAuth, TEACH, asyncHandler(async (req, res) => {
    const s = (await pool.query(
      'SELECT s.*, a.course_id, a.max_score, a.title FROM submissions s JOIN assignments a ON a.id=s.assignment_id WHERE s.id=$1',
      [req.params.id])).rows[0];
    if (!s) throw C.err(404, 'Rendu introuvable.');
    await C.ownCourse(s.course_id, req.user);
    const { score, feedback } = req.body;
    if (score != null && (Number(score) < 0 || Number(score) > Number(s.max_score))) throw C.err(400, `Note entre 0 et ${s.max_score}.`);
    await pool.query('UPDATE submissions SET score=COALESCE($2,score), feedback=COALESCE($3,feedback) WHERE id=$1',
      [s.id, score ?? null, feedback ?? null]);
    res.json({ message: 'Rendu corrigé.' });
  }));
};

// ============================== MODULE : grades ==============================
const mod_grades = (d, C) => {
  const { router, pool, crypto, requireAuth, requireRole, asyncHandler, audit, notifyUser, currentAcademicYear } = d;
  const TEACH = requireRole('enseignant', 'scolarite', 'admin');
  const SCOL = requireRole('scolarite', 'admin');

  // ---------- Outils PDF / codes de vérification (partagés avec les autres modules) ----------
  C.pdfToBuffer = (build) => new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 50, size: 'A4' });
    const chunks = [];
    doc.on('data', (c) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
    Promise.resolve(build(doc)).then(() => doc.end()).catch(reject);
  });
  C.issueCode = async (type, studentId, academicYear, payload) => {
    const code = crypto.randomBytes(6).toString('hex').toUpperCase();
    await pool.query(
      'INSERT INTO issued_documents (id, code, type, student_id, academic_year, payload) VALUES ($1,$2,$3,$4,$5,$6)',
      [crypto.randomUUID(), code, type, studentId, academicYear || null, payload || {}]);
    return code;
  };
  C.verifyUrl = (code) => `${process.env.PUBLIC_URL || 'http://localhost:3000'}/verify/${code}`;
  C.pdfHeader = async (doc, title) => {
    const inst = await C.getSetting('institution_name', 'UniConnect - Universite');
    doc.fontSize(18).fillColor('#1A365D').text(inst, { align: 'center' });
    doc.moveDown(0.3).fontSize(14).fillColor('#000').text(title, { align: 'center' });
    doc.moveDown(1);
  };
  C.pdfFooterQr = async (doc, code) => {
    const png = await QRCode.toBuffer(C.verifyUrl(code), { margin: 1, width: 120 });
    const y = doc.page.height - 170;
    doc.image(png, 50, y, { width: 100 });
    doc.fontSize(9).fillColor('#444').text(`Code de verification : ${code}`, 160, y + 30)
      .text("Scannez le QR code pour verifier l'authenticite de ce document.", 160, y + 45);
  };
  C.studentIdentity = async (studentId) =>
    (await pool.query(
      `SELECT u.full_name, s.matricule, s.birth_date, s.academic_year, p.name AS program, l.name AS level
       FROM users u JOIN students s ON s.user_id=u.id LEFT JOIN programs p ON p.id=s.program_id
       LEFT JOIN levels l ON l.id=s.level_id WHERE u.id=$1`, [studentId])).rows[0];

  async function transcriptPdf(studentId, year, semester) {
    const who = await C.studentIdentity(studentId);
    if (!who) throw C.err(404, 'Étudiant introuvable.');
    const sum = await C.computeSummary(studentId, year, semester);
    const code = await C.issueCode('releve_notes', studentId, year, { semester: semester || null });
    return C.pdfToBuffer(async (doc) => {
      await C.pdfHeader(doc, 'RELEVE DE NOTES');
      doc.fontSize(11).fillColor('#000')
        .text(`Nom : ${who.full_name}`).text(`Matricule : ${who.matricule}`)
        .text(`Filiere : ${who.program || '-'}   Niveau : ${who.level || '-'}`).moveDown();
      if (!sum.courses.length) doc.text('Aucune note publiee.');
      for (const s of sum.semesters) {
        doc.fontSize(12).fillColor('#1A365D').text(`${s.academicYear || ''} - Semestre ${s.semester}`).moveDown(0.3);
        doc.fontSize(10).fillColor('#000').font('Helvetica');
        for (const c of sum.courses.filter((x) => x.academicYear === s.academicYear && x.semester === s.semester)) {
          doc.text(`${c.code}  ${c.title}  |  credits ${c.credits}  |  moyenne ${c.average.toFixed(2)}/20  |  ${c.validated ? 'Valide' : 'Non valide'}`);
        }
        doc.moveDown(0.3).font('Helvetica-Bold')
          .text(`Moyenne : ${s.average.toFixed(2)}/20 - ${s.mention} - Credits ${s.creditsEarned}/${s.creditsTotal} - ${s.decision}`)
          .font('Helvetica').moveDown();
      }
      await C.pdfFooterQr(doc, code);
    });
  }
  C.transcriptPdf = transcriptPdf;

  // ---------- Consultation étudiant ----------
  router.get('/grades/me', requireAuth, requireRole('etudiant'), asyncHandler(async (req, res) => {
    if (await C.isBlockedForUnpaid(req.user.id)) throw C.err(403, 'Accès aux notes suspendu : régularisez vos frais de scolarité.');
    const rows = (await pool.query(
      `SELECT g.*, c.code AS course_code, c.title AS course_title, c.credits
       FROM grades g JOIN courses c ON c.id=g.course_id WHERE g.student_id=$1 AND g.status='publie'
       ORDER BY g.academic_year DESC, g.semester, c.code`, [req.user.id])).rows;
    const claims = new Map((await pool.query('SELECT grade_id, status FROM grade_claims WHERE student_id=$1', [req.user.id])).rows.map((c) => [c.grade_id, c.status]));
    res.json(rows.map((g) => ({
      id: g.id, courseCode: g.course_code, courseTitle: g.course_title, credits: g.credits,
      evaluationName: g.evaluation_name, score: Number(g.score), maxScore: Number(g.max_score),
      coefficient: Number(g.coefficient), academicYear: g.academic_year, semester: g.semester,
      publishedAt: g.published_at, claimStatus: claims.get(g.id) || null,
    })));
  }));
  router.get('/grades/me/summary', requireAuth, requireRole('etudiant'), asyncHandler(async (req, res) => {
    if (await C.isBlockedForUnpaid(req.user.id)) throw C.err(403, 'Accès aux notes suspendu : régularisez vos frais de scolarité.');
    res.json(await C.computeSummary(req.user.id, req.query.academicYear, req.query.semester ? Number(req.query.semester) : null));
  }));
  router.get('/transcripts/me/pdf', requireAuth, requireRole('etudiant'), asyncHandler(async (req, res) => {
    if (await C.isBlockedForUnpaid(req.user.id)) throw C.err(403, 'Relevé suspendu : régularisez vos frais.');
    const buf = await transcriptPdf(req.user.id, req.query.academicYear, req.query.semester ? Number(req.query.semester) : null);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'inline; filename="releve-notes.pdf"');
    res.send(buf);
  }));
  router.get('/transcripts/:studentId/pdf', requireAuth, SCOL, asyncHandler(async (req, res) => {
    const buf = await transcriptPdf(req.params.studentId, req.query.academicYear, req.query.semester ? Number(req.query.semester) : null);
    res.setHeader('Content-Type', 'application/pdf');
    res.send(buf);
  }));

  // ---------- Saisie par l'enseignant ----------
  async function checkEntry(user, { studentId, courseId, score, maxScore }) {
    const course = await C.ownCourse(courseId, user);
    const max = Number(maxScore || 20);
    if (Number.isNaN(Number(score)) || Number(score) < 0 || Number(score) > max) throw C.err(400, `La note doit être comprise entre 0 et ${max}.`);
    if (!(await C.studentInCourse(studentId, courseId, currentAcademicYear()))) {
      const any = (await pool.query('SELECT 1 FROM enrollments WHERE student_id=$1 AND course_id=$2', [studentId, courseId])).rowCount;
      if (!any) throw C.err(400, "L'étudiant n'est pas inscrit à ce cours.");
    }
    return course;
  }
  async function upsertGrade(user, e, status) {
    const year = e.academicYear || currentAcademicYear();
    const sem = Number(e.semester || 1);
    const ex = (await pool.query(
      `SELECT * FROM grades WHERE student_id=$1 AND course_id=$2 AND evaluation_name=$3 AND academic_year=$4 AND semester=$5`,
      [e.studentId, e.courseId, e.evaluationName, year, sem])).rows[0];
    if (ex) {
      if (ex.status === 'publie') throw C.err(409, 'Note déjà publiée : modification réservée à la scolarité (avec motif).');
      await pool.query('UPDATE grades SET score=$2, max_score=$3, coefficient=$4, status=$5, updated_at=now() WHERE id=$1',
        [ex.id, e.score, e.maxScore || ex.max_score, e.coefficient || ex.coefficient, status]);
      return ex.id;
    }
    const id = crypto.randomUUID();
    await pool.query(
      `INSERT INTO grades (id, student_id, course_id, evaluation_name, score, max_score, coefficient, academic_year, semester, status, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [id, e.studentId, e.courseId, e.evaluationName, e.score, e.maxScore || 20, e.coefficient || 1, year, sem, status, user.id]);
    return id;
  }
  router.post('/grades', requireAuth, TEACH, asyncHandler(async (req, res) => {
    const b = req.body;
    if (!b.studentId || !b.courseId || !b.evaluationName || b.score == null) throw C.err(400, 'Champs obligatoires manquants.');
    await checkEntry(req.user, b);
    const status = req.user.role === 'enseignant' ? 'brouillon' : 'soumis';
    const id = await upsertGrade(req.user, b, status);
    res.status(201).json({ id, message: status === 'brouillon' ? 'Note enregistrée en brouillon.' : 'Note enregistrée.' });
  }));
  router.post('/grades/batch', requireAuth, TEACH, asyncHandler(async (req, res) => {
    const { courseId, evaluationName, maxScore, coefficient, academicYear, semester, entries } = req.body;
    if (!courseId || !evaluationName || !Array.isArray(entries) || !entries.length) throw C.err(400, 'courseId, evaluationName et entries requis.');
    let saved = 0; const errors = [];
    const status = req.user.role === 'enseignant' ? 'brouillon' : 'soumis';
    for (const en of entries) {
      if (en.score == null || en.score === '') continue;
      try {
        const e = { studentId: en.studentId, courseId, evaluationName, maxScore, coefficient, academicYear, semester, score: Number(en.score) };
        await checkEntry(req.user, e);
        await upsertGrade(req.user, e, status);
        saved += 1;
      } catch (err) { errors.push({ studentId: en.studentId, message: err.message }); }
    }
    res.json({ saved, errors });
  }));
  router.get('/courses/:id/grades', requireAuth, TEACH, asyncHandler(async (req, res) => {
    await C.ownCourse(req.params.id, req.user);
    const rows = (await pool.query(
      `SELECT g.*, u.full_name, s.matricule FROM grades g JOIN users u ON u.id=g.student_id
       LEFT JOIN students s ON s.user_id=g.student_id WHERE g.course_id=$1 ORDER BY g.evaluation_name, u.full_name`, [req.params.id])).rows;
    res.json(rows.map((g) => ({ id: g.id, studentId: g.student_id, studentName: g.full_name, matricule: g.matricule,
      evaluationName: g.evaluation_name, score: Number(g.score), maxScore: Number(g.max_score), coefficient: Number(g.coefficient),
      academicYear: g.academic_year, semester: g.semester, status: g.status })));
  }));

  /** Modification : libre avant publication (enseignant), avec motif et historique après (scolarité). */
  router.patch('/grades/:id', requireAuth, TEACH, asyncHandler(async (req, res) => {
    const g = (await pool.query('SELECT g.*, c.title FROM grades g JOIN courses c ON c.id=g.course_id WHERE g.id=$1', [req.params.id])).rows[0];
    if (!g) throw C.err(404, 'Note introuvable.');
    const { score, motif } = req.body;
    await checkEntry(req.user, { studentId: g.student_id, courseId: g.course_id, score, maxScore: g.max_score });
    if (g.status === 'publie') {
      if (!['scolarite', 'admin'].includes(req.user.role)) throw C.err(403, 'Seule la scolarité modifie une note publiée.');
      if (!motif || motif.trim().length < 5) throw C.err(400, 'Un motif est obligatoire.');
      await pool.query('INSERT INTO grade_history (id, grade_id, old_score, new_score, motif, changed_by) VALUES ($1,$2,$3,$4,$5,$6)',
        [crypto.randomUUID(), g.id, g.score, score, motif, req.user.id]);
      await notifyUser(g.student_id, 'grade_published', { course: g.title }, { courseId: g.course_id });
    }
    await pool.query('UPDATE grades SET score=$2, updated_at=now() WHERE id=$1', [g.id, score]);
    await audit(req.user.id, 'update_grade', 'grade', g.id, { old: g.score, new: score, motif }, req.ip);
    res.json({ message: 'Note modifiée.' });
  }));
  router.get('/grades/:id/history', requireAuth, SCOL, asyncHandler(async (req, res) => {
    res.json((await pool.query(
      `SELECT h.*, u.full_name AS changed_by_name FROM grade_history h LEFT JOIN users u ON u.id=h.changed_by
       WHERE h.grade_id=$1 ORDER BY h.created_at DESC`, [req.params.id])).rows);
  }));

  // ---------- Soumission puis publication ----------
  router.post('/grades/submit', requireAuth, TEACH, asyncHandler(async (req, res) => {
    const { courseId, academicYear, semester } = req.body;
    await C.ownCourse(courseId, req.user);
    const r = await pool.query(
      `UPDATE grades SET status='soumis', updated_at=now()
       WHERE course_id=$1 AND academic_year=$2 AND semester=$3 AND status='brouillon' RETURNING id`,
      [courseId, academicYear || currentAcademicYear(), Number(semester || 1)]);
    await audit(req.user.id, 'submit_grades', 'course', courseId, { count: r.rowCount }, req.ip);
    res.json({ message: `${r.rowCount} note(s) soumise(s) à la scolarité.` });
  }));
  router.get('/admin/grades/pending', requireAuth, SCOL, asyncHandler(async (req, res) => {
    res.json((await pool.query(
      `SELECT g.course_id, c.code, c.title, g.academic_year, g.semester, COUNT(*) AS count, u.full_name AS teacher_name
       FROM grades g JOIN courses c ON c.id=g.course_id LEFT JOIN users u ON u.id=c.teacher_id
       WHERE g.status='soumis' GROUP BY g.course_id, c.code, c.title, g.academic_year, g.semester, u.full_name
       ORDER BY c.code`)).rows);
  }));
  router.post('/grades/publish', requireAuth, SCOL, asyncHandler(async (req, res) => {
    const { courseId, academicYear, semester } = req.body;
    if (!courseId) throw C.err(400, 'courseId requis.');
    const result = await pool.query(
      `UPDATE grades SET status='publie', published_at=now(), updated_at=now()
       WHERE course_id=$1 AND academic_year=$2 AND semester=$3 AND status='soumis' RETURNING student_id`,
      [courseId, academicYear || currentAcademicYear(), Number(semester || 1)]);
    const course = (await pool.query('SELECT title FROM courses WHERE id=$1', [courseId])).rows[0];
    for (const sid of new Set(result.rows.map((r) => r.student_id))) {
      await notifyUser(sid, 'grade_published', { course: course?.title || '' }, { courseId });
    }
    await audit(req.user.id, 'publish_grades', 'course', courseId, { count: result.rowCount }, req.ip);
    res.json({ message: `${result.rowCount} note(s) publiée(s).` });
  }));

  // ---------- Réclamations ----------
  router.post('/grades/:id/claims', requireAuth, requireRole('etudiant'), asyncHandler(async (req, res) => {
    const g = (await pool.query(
      `SELECT g.*, c.title, c.teacher_id FROM grades g JOIN courses c ON c.id=g.course_id
       WHERE g.id=$1 AND g.student_id=$2 AND g.status='publie'`, [req.params.id, req.user.id])).rows[0];
    if (!g) throw C.err(404, 'Note introuvable.');
    const windowDays = Number(await C.getSetting('claim_window_days', '15'));
    if (Date.now() - new Date(g.published_at).getTime() > windowDays * 86400000) throw C.err(400, `Délai de réclamation dépassé (${windowDays} jours).`);
    if (!req.body.motif || req.body.motif.trim().length < 10) throw C.err(400, 'Motif détaillé requis (10 caractères minimum).');
    try {
      await pool.query('INSERT INTO grade_claims (id, grade_id, student_id, motif) VALUES ($1,$2,$3,$4)',
        [crypto.randomUUID(), g.id, req.user.id, req.body.motif.trim()]);
    } catch (e) { if (e.code === '23505') throw C.err(409, 'Une réclamation existe déjà pour cette note.'); throw e; }
    if (g.teacher_id) await notifyUser(g.teacher_id, 'claim_new', { student: req.user.name, course: g.title }, { gradeId: g.id });
    res.status(201).json({ message: 'Réclamation enregistrée.' });
  }));
  router.get('/claims/me', requireAuth, requireRole('etudiant'), asyncHandler(async (req, res) => {
    res.json((await pool.query(
      `SELECT gc.*, g.evaluation_name, g.score, c.code FROM grade_claims gc JOIN grades g ON g.id=gc.grade_id
       JOIN courses c ON c.id=g.course_id WHERE gc.student_id=$1 ORDER BY gc.created_at DESC`, [req.user.id])).rows);
  }));
  router.get('/claims', requireAuth, TEACH, asyncHandler(async (req, res) => {
    const p = []; let w = '1=1';
    if (req.user.role === 'enseignant') { p.push(req.user.id); w += ` AND c.teacher_id=$${p.length}`; }
    if (req.query.status) { p.push(req.query.status); w += ` AND gc.status=$${p.length}`; }
    res.json((await pool.query(
      `SELECT gc.*, g.evaluation_name, g.score, g.max_score, c.code, c.title, u.full_name AS student_name, s.matricule
       FROM grade_claims gc JOIN grades g ON g.id=gc.grade_id JOIN courses c ON c.id=g.course_id
       JOIN users u ON u.id=gc.student_id LEFT JOIN students s ON s.user_id=gc.student_id
       WHERE ${w} ORDER BY gc.created_at DESC`, p)).rows);
  }));
  router.patch('/claims/:id', requireAuth, TEACH, asyncHandler(async (req, res) => {
    const gc = (await pool.query(
      `SELECT gc.*, g.course_id, g.score AS old_score, g.max_score, c.title FROM grade_claims gc
       JOIN grades g ON g.id=gc.grade_id JOIN courses c ON c.id=g.course_id WHERE gc.id=$1`, [req.params.id])).rows[0];
    if (!gc) throw C.err(404, 'Réclamation introuvable.');
    await C.ownCourse(gc.course_id, req.user);
    const { status, response, newScore } = req.body;
    if (!['acceptee', 'rejetee'].includes(status) || !response) throw C.err(400, 'status (acceptee|rejetee) et response requis.');
    if (status === 'acceptee' && newScore != null) {
      if (Number(newScore) < 0 || Number(newScore) > Number(gc.max_score)) throw C.err(400, 'Note hors barème.');
      await pool.query('INSERT INTO grade_history (id, grade_id, old_score, new_score, motif, changed_by) VALUES ($1,$2,$3,$4,$5,$6)',
        [crypto.randomUUID(), gc.grade_id, gc.old_score, newScore, `Réclamation acceptée : ${response}`, req.user.id]);
      await pool.query('UPDATE grades SET score=$2, updated_at=now() WHERE id=$1', [gc.grade_id, newScore]);
    }
    await pool.query('UPDATE grade_claims SET status=$2, response=$3, handled_by=$4, handled_at=now() WHERE id=$1',
      [gc.id, status, response, req.user.id]);
    await notifyUser(gc.student_id, 'claim_reply', { course: gc.title, status: status === 'acceptee' ? 'acceptée' : 'rejetée' }, { claimId: gc.id });
    await audit(req.user.id, 'handle_claim', 'grade_claim', gc.id, { status, newScore }, req.ip);
    res.json({ message: 'Réclamation traitée.' });
  }));
};

// ============================== MODULE : attendance ==============================
const mod_attendance = (d, C) => {
  const { router, pool, crypto, requireAuth, requireRole, asyncHandler, audit, notifyUser, upload,
    currentAcademicYear } = d;
  const TEACH = requireRole('enseignant', 'scolarite', 'admin');
  const ROTATION = 30;

  const qrToken = (secret, ts) => crypto.createHmac('sha256', secret).update(String(ts)).digest('hex').slice(0, 24);
  const nowTs = () => Math.floor(Date.now() / 1000 / ROTATION);
  const safeEq = (a, b) => {
    const x = Buffer.from(String(a)); const y = Buffer.from(String(b));
    return x.length === y.length && crypto.timingSafeEqual(x, y);
  };
  function distanceM(lat1, lon1, lat2, lon2) {
    const R = 6371000; const rad = (v) => (v * Math.PI) / 180;
    const a = Math.sin(rad(lat2 - lat1) / 2) ** 2 + Math.cos(rad(lat1)) * Math.cos(rad(lat2)) * Math.sin(rad(lon2 - lon1) / 2) ** 2;
    return 2 * R * Math.asin(Math.sqrt(a));
  }
  async function getSession(id, user) {
    const s = (await pool.query('SELECT * FROM attendance_sessions WHERE id=$1', [id])).rows[0];
    if (!s) throw C.err(404, 'Session introuvable.');
    if (user.role === 'enseignant' && s.teacher_id !== user.id) throw C.err(403, 'Cette séance ne vous appartient pas.');
    return s;
  }
  const payloadFor = (s) => {
    const ts = nowTs();
    return { ts, payload: Buffer.from(JSON.stringify({ sessionId: s.id, ts, token: qrToken(s.qr_secret, ts) })).toString('base64') };
  };

  // ---------- Ouverture / QR dynamique / fermeture ----------
  router.post('/attendance/sessions', requireAuth, TEACH, asyncHandler(async (req, res) => {
    const { courseId, roomId, durationMinutes } = req.body;
    if (!courseId) throw C.err(400, 'courseId requis.');
    await C.ownCourse(courseId, req.user);
    const open = (await pool.query(
      `SELECT id FROM attendance_sessions WHERE course_id=$1 AND teacher_id=$2 AND status='ouverte' AND expires_at>now()`, [courseId, req.user.id])).rows[0];
    if (open) throw C.err(409, 'Une séance est déjà ouverte pour ce cours.');
    const id = crypto.randomUUID();
    const expires = new Date(Date.now() + (Number(durationMinutes) || 30) * 60000);
    await pool.query(
      'INSERT INTO attendance_sessions (id, course_id, teacher_id, room_id, expires_at, qr_secret) VALUES ($1,$2,$3,$4,$5,$6)',
      [id, courseId, req.user.id, roomId || null, expires, crypto.randomBytes(24).toString('hex')]);
    const s = (await pool.query('SELECT * FROM attendance_sessions WHERE id=$1', [id])).rows[0];
    res.status(201).json({ sessionId: id, expiresAt: expires.toISOString(), rotationSeconds: ROTATION, ...payloadFor(s) });
  }));
  /** Le QR courant (change toutes les 30 s) : le secret ne quitte jamais le serveur. */
  router.get('/attendance/sessions/:id/qr', requireAuth, TEACH, asyncHandler(async (req, res) => {
    const s = await getSession(req.params.id, req.user);
    if (s.status !== 'ouverte' || new Date(s.expires_at) < new Date()) throw C.err(400, 'Séance terminée.');
    res.json(payloadFor(s));
  }));
  router.post('/attendance/sessions/:id/close', requireAuth, TEACH, asyncHandler(async (req, res) => {
    const s = await getSession(req.params.id, req.user);
    await pool.query(`UPDATE attendance_sessions SET status='fermee', closed_at=now() WHERE id=$1`, [s.id]);
    await C.checkAbsenceAlerts(s.course_id);
    res.json({ message: 'Séance clôturée.' });
  }));

  // ---------- Marquage par l'étudiant ----------
  router.post('/attendance/mark', requireAuth, requireRole('etudiant'), asyncHandler(async (req, res) => {
    const { sessionId, qrPayload, deviceId, latitude, longitude } = req.body;
    if (!sessionId || !qrPayload) throw C.err(400, 'sessionId et qrPayload requis.');
    if (!deviceId) throw C.err(400, "Identifiant d'appareil requis.");
    const s = (await pool.query(`SELECT * FROM attendance_sessions WHERE id=$1 AND status='ouverte'`, [sessionId])).rows[0];
    if (!s) throw C.err(404, 'Session invalide ou fermée.');
    if (new Date(s.expires_at) < new Date()) throw C.err(400, 'Session expirée.');
    let p;
    try { p = JSON.parse(Buffer.from(qrPayload, 'base64').toString('utf8')); } catch { throw C.err(400, 'QR invalide.'); }
    if (p.sessionId !== sessionId) throw C.err(400, 'QR non reconnu.');
    const ts = Number(p.ts);
    if (Math.abs(ts - nowTs()) > 1 || !p.token || !safeEq(p.token, qrToken(s.qr_secret, ts))) throw C.err(400, 'QR expiré ou falsifié.');
    if (!(await C.studentInCourse(req.user.id, s.course_id, currentAcademicYear()))) throw C.err(403, 'Vous ne suivez pas ce cours.');

    // Géolocalisation : l'étudiant doit être près de la salle
    if (s.room_id) {
      const room = (await pool.query('SELECT latitude, longitude FROM rooms WHERE id=$1', [s.room_id])).rows[0];
      if (room && room.latitude != null && room.longitude != null) {
        if (latitude == null || longitude == null) throw C.err(400, 'Activez la localisation pour valider votre présence.');
        const max = Number(await C.getSetting('geofence_meters', '150'));
        const dist = distanceM(Number(latitude), Number(longitude), Number(room.latitude), Number(room.longitude));
        if (dist > max) throw C.err(403, `Vous semblez éloigné de la salle (${Math.round(dist)} m).`);
      }
    }
    // Appareil enregistré : un étudiant = un téléphone ; un téléphone = un étudiant par séance
    const st = (await pool.query('SELECT device_id FROM students WHERE user_id=$1', [req.user.id])).rows[0];
    if (st && st.device_id && st.device_id !== deviceId) throw C.err(403, 'Appareil non reconnu. Demandez la réinitialisation à la scolarité.');
    const dup = await pool.query('SELECT 1 FROM attendances WHERE session_id=$1 AND device_id=$2 AND student_id<>$3', [sessionId, deviceId, req.user.id]);
    if (dup.rowCount) throw C.err(403, "Cet appareil a déjà validé la présence d'un autre étudiant.");
    if (st && !st.device_id) await pool.query('UPDATE students SET device_id=$2 WHERE user_id=$1', [req.user.id, deviceId]);

    try {
      await pool.query(
        `INSERT INTO attendances (id, session_id, student_id, method, device_id, latitude, longitude) VALUES ($1,$2,$3,'qr',$4,$5,$6)`,
        [crypto.randomUUID(), sessionId, req.user.id, deviceId, latitude ?? null, longitude ?? null]);
    } catch (e) { if (e.code === '23505') throw C.err(409, 'Déjà marqué présent.'); throw e; }
    res.json({ message: 'Présence enregistrée.' });
  }));
  router.post('/admin/students/:id/reset-device', requireAuth, requireRole('admin', 'scolarite'), asyncHandler(async (req, res) => {
    await pool.query('UPDATE students SET device_id=NULL WHERE user_id=$1', [req.params.id]);
    await audit(req.user.id, 'reset_device', 'user', req.params.id, null, req.ip);
    res.json({ message: 'Appareil réinitialisé.' });
  }));

  // ---------- Listes et corrections par l'enseignant ----------
  router.get('/attendance/sessions/:id/list', requireAuth, TEACH, asyncHandler(async (req, res) => {
    const s = await getSession(req.params.id, req.user);
    const rows = (await pool.query(
      `SELECT a.*, u.full_name, st.matricule FROM attendances a JOIN users u ON u.id=a.student_id
       LEFT JOIN students st ON st.user_id=a.student_id WHERE a.session_id=$1 ORDER BY a.marked_at`, [s.id])).rows;
    res.json(rows.map((r) => ({ id: r.id, studentId: r.student_id, studentName: r.full_name, matricule: r.matricule, markedAt: r.marked_at, method: r.method })));
  }));
  router.get('/attendance/sessions/:id/sheet', requireAuth, TEACH, asyncHandler(async (req, res) => {
    const s = await getSession(req.params.id, req.user);
    const roster = await C.roster(s.course_id, currentAcademicYear());
    const present = new Map((await pool.query('SELECT student_id, method FROM attendances WHERE session_id=$1', [s.id])).rows.map((r) => [r.student_id, r.method]));
    res.json(roster.map((r) => ({ studentId: r.id, studentName: r.full_name, matricule: r.matricule, present: present.has(r.id), method: present.get(r.id) || null })));
  }));
  router.post('/attendance/sessions/:id/manual', requireAuth, TEACH, asyncHandler(async (req, res) => {
    const s = await getSession(req.params.id, req.user);
    const { studentId, present } = req.body;
    if (!studentId) throw C.err(400, 'studentId requis.');
    if (present === false) {
      await pool.query('DELETE FROM attendances WHERE session_id=$1 AND student_id=$2', [s.id, studentId]);
    } else {
      await pool.query(
        `INSERT INTO attendances (id, session_id, student_id, method) VALUES ($1,$2,$3,'manuel') ON CONFLICT (session_id, student_id) DO NOTHING`,
        [crypto.randomUUID(), s.id, studentId]);
    }
    await audit(req.user.id, 'manual_attendance', 'attendance_session', s.id, { studentId, present }, req.ip);
    res.json({ message: 'Liste corrigée.' });
  }));

  // ---------- Assiduité ----------
  /** Séances tenues = fermées ou expirées. */
  const HELD = `(s.status='fermee' OR s.expires_at < now())`;
  router.get('/attendance/me', requireAuth, requireRole('etudiant'), asyncHandler(async (req, res) => {
    const ids = await C.studentCourseIds(req.user.id, currentAcademicYear());
    const rows = (await pool.query(
      `SELECT s.id AS session_id, s.started_at, c.id AS course_id, c.code, c.title,
              (a.id IS NOT NULL) AS present, j.status AS justification
       FROM attendance_sessions s JOIN courses c ON c.id=s.course_id
       LEFT JOIN attendances a ON a.session_id=s.id AND a.student_id=$1
       LEFT JOIN absence_justifications j ON j.session_id=s.id AND j.student_id=$1
       WHERE s.course_id = ANY($2) AND ${HELD} ORDER BY s.started_at DESC`, [req.user.id, ids])).rows;
    const byCourse = new Map();
    for (const r of rows) {
      if (!byCourse.has(r.course_id)) byCourse.set(r.course_id, { courseId: r.course_id, code: r.code, title: r.title, held: 0, present: 0 });
      const c = byCourse.get(r.course_id); c.held += 1; if (r.present) c.present += 1;
    }
    res.json({
      courses: [...byCourse.values()].map((c) => ({ ...c, rate: c.held ? Math.round((c.present / c.held) * 100) : 100 })),
      absences: rows.filter((r) => !r.present).map((r) => ({ sessionId: r.session_id, code: r.code, title: r.title, date: r.started_at, justification: r.justification })),
    });
  }));
  router.get('/attendance/courses/:id/report', requireAuth, TEACH, asyncHandler(async (req, res) => {
    await C.ownCourse(req.params.id, req.user);
    const held = Number((await pool.query(`SELECT COUNT(*) FROM attendance_sessions s WHERE s.course_id=$1 AND ${HELD}`, [req.params.id])).rows[0].count);
    const roster = await C.roster(req.params.id, currentAcademicYear());
    const pres = new Map((await pool.query(
      `SELECT a.student_id, COUNT(*) AS n FROM attendances a JOIN attendance_sessions s ON s.id=a.session_id
       WHERE s.course_id=$1 AND ${HELD} GROUP BY a.student_id`, [req.params.id])).rows.map((r) => [r.student_id, Number(r.n)]));
    res.json({ held, students: roster.map((r) => ({ studentId: r.id, studentName: r.full_name, matricule: r.matricule,
      present: pres.get(r.id) || 0, rate: held ? Math.round(((pres.get(r.id) || 0) / held) * 100) : 100 })) });
  }));

  // ---------- Justificatifs d'absence ----------
  router.post('/attendance/justifications', requireAuth, requireRole('etudiant'), upload.single('file'), asyncHandler(async (req, res) => {
    const { sessionId, reason } = req.body;
    if (!sessionId || !reason) throw C.err(400, 'sessionId et motif requis.');
    const s = (await pool.query('SELECT course_id FROM attendance_sessions WHERE id=$1', [sessionId])).rows[0];
    if (!s || !(await C.studentInCourse(req.user.id, s.course_id, currentAcademicYear()))) throw C.err(404, 'Séance introuvable.');
    const fileId = await C.saveFile(req.file, req.user.id);
    try {
      await pool.query('INSERT INTO absence_justifications (id, session_id, student_id, reason, file_id) VALUES ($1,$2,$3,$4,$5)',
        [crypto.randomUUID(), sessionId, req.user.id, reason, fileId]);
    } catch (e) { if (e.code === '23505') throw C.err(409, 'Justificatif déjà envoyé.'); throw e; }
    res.status(201).json({ message: 'Justificatif envoyé à la scolarité.' });
  }));
  router.get('/attendance/justifications', requireAuth, requireRole('scolarite', 'admin'), asyncHandler(async (req, res) => {
    res.json((await pool.query(
      `SELECT j.*, u.full_name, st.matricule, c.code, s.started_at FROM absence_justifications j
       JOIN users u ON u.id=j.student_id LEFT JOIN students st ON st.user_id=j.student_id
       JOIN attendance_sessions s ON s.id=j.session_id JOIN courses c ON c.id=s.course_id
       WHERE j.status=COALESCE($1, j.status) ORDER BY j.created_at DESC`, [req.query.status || 'en_attente'])).rows
      .map((j) => ({ ...j, fileUrl: C.fileUrl(j.file_id) })));
  }));
  router.patch('/attendance/justifications/:id', requireAuth, requireRole('scolarite', 'admin'), asyncHandler(async (req, res) => {
    if (!['acceptee', 'rejetee'].includes(req.body.status)) throw C.err(400, 'status invalide.');
    const j = (await pool.query('UPDATE absence_justifications SET status=$2 WHERE id=$1 RETURNING *', [req.params.id, req.body.status])).rows[0];
    if (!j) throw C.err(404, 'Justificatif introuvable.');
    await notifyUser(j.student_id, 'absence_justification', { status: req.body.status === 'acceptee' ? 'accepté' : 'refusé' }, { sessionId: j.session_id });
    res.json({ message: 'Justificatif traité.' });
  }));

  // ---------- Alertes d'absences répétées ----------
  C.checkAbsenceAlerts = async (courseId) => {
    const threshold = Number(await C.getSetting('absence_threshold', '3'));
    const year = currentAcademicYear();
    const course = (await pool.query('SELECT title FROM courses WHERE id=$1', [courseId])).rows[0];
    if (!course) return;
    const rows = (await pool.query(
      `SELECT r.id AS student_id, COUNT(*) AS missed FROM (
         SELECT e.student_id AS id FROM enrollments e WHERE e.course_id=$1 AND e.academic_year=$2 AND e.status='inscrit') r
       JOIN attendance_sessions s ON s.course_id=$1 AND ${HELD}
       LEFT JOIN attendances a ON a.session_id=s.id AND a.student_id=r.id
       LEFT JOIN absence_justifications j ON j.session_id=s.id AND j.student_id=r.id AND j.status='acceptee'
       WHERE a.id IS NULL AND j.id IS NULL GROUP BY r.id HAVING COUNT(*) >= $3`, [courseId, year, threshold])).rows;
    const staff = (await pool.query(`SELECT id FROM users WHERE role='scolarite' AND is_active`)).rows;
    for (const r of rows) {
      const ins = await pool.query(
        'INSERT INTO attendance_alerts_sent (student_id, course_id, academic_year) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING RETURNING 1', [r.student_id, courseId, year]);
      if (!ins.rowCount) continue;
      const name = (await pool.query('SELECT full_name FROM users WHERE id=$1', [r.student_id])).rows[0]?.full_name || '';
      await notifyUser(r.student_id, 'attendance_alert', { course: course.title }, { courseId });
      for (const u of staff) await notifyUser(u.id, 'attendance_alert_staff', { student: name, count: r.missed, course: course.title }, { courseId });
    }
  };
};

// ============================== MODULE : finance ==============================
const mod_finance = (d, C) => {
  const { router, pool, crypto, axios, requireAuth, requireRole, asyncHandler, audit, notifyUser,
    currentAcademicYear } = d;
  const ACC = requireRole('comptabilite', 'admin');
  const ACC_VIEW = requireRole('comptabilite', 'admin', 'directeur');
  const SANDBOX = process.env.PAYMENT_SANDBOX === 'true';
  const toCsv = (rows) => {
    if (!rows.length) return '';
    const keys = Object.keys(rows[0]);
    const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
    return '\uFEFF' + [keys.join(';'), ...rows.map((r) => keys.map((k) => esc(r[k])).join(';'))].join('\n');
  };
  C.toCsv = toCsv;

  // ---------- Définition des frais et affectation automatique ----------
  router.get('/accounting/fees', requireAuth, ACC_VIEW, asyncHandler(async (req, res) => {
    const r = await pool.query(
      `SELECT f.*, p.name AS program_name, l.name AS level_name,
              (SELECT COUNT(*) FROM student_fees sf WHERE sf.fee_id=f.id) AS students
       FROM fees f LEFT JOIN programs p ON p.id=f.program_id LEFT JOIN levels l ON l.id=f.level_id
       ORDER BY f.academic_year DESC, f.due_date NULLS LAST`);
    res.json(r.rows);
  }));
  router.post('/accounting/fees', requireAuth, ACC, asyncHandler(async (req, res) => {
    const { label, amountFcfa, academicYear, dueDate, programId, levelId } = req.body;
    if (!label || !Number.isInteger(Number(amountFcfa)) || Number(amountFcfa) <= 0) throw C.err(400, 'Libellé et montant (FCFA, entier positif) requis.');
    const id = crypto.randomUUID();
    await pool.query(
      'INSERT INTO fees (id, program_id, level_id, academic_year, label, amount_fcfa, due_date) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [id, programId || null, levelId || null, academicYear || currentAcademicYear(), label, Number(amountFcfa), dueDate || null]);
    const r = await pool.query(
      `INSERT INTO student_fees (id, student_id, fee_id, amount_due_fcfa)
       SELECT gen_random_uuid(), s.user_id, f.id, f.amount_fcfa FROM fees f
       JOIN students s ON (f.program_id IS NULL OR s.program_id=f.program_id) AND (f.level_id IS NULL OR s.level_id=f.level_id)
       JOIN users u ON u.id=s.user_id AND u.is_active WHERE f.id=$1
       RETURNING 1`, [id]);
    await audit(req.user.id, 'create_fee', 'fee', id, req.body, req.ip);
    res.status(201).json({ id, assigned: r.rowCount });
  }));
  router.delete('/accounting/fees/:id', requireAuth, requireRole('admin'), asyncHandler(async (req, res) => {
    const paid = await pool.query('SELECT 1 FROM student_fees WHERE fee_id=$1 AND amount_paid_fcfa>0 LIMIT 1', [req.params.id]);
    if (paid.rowCount) throw C.err(409, 'Des paiements existent : suppression impossible.');
    await pool.query('DELETE FROM student_fees WHERE fee_id=$1', [req.params.id]);
    await pool.query('DELETE FROM fees WHERE id=$1', [req.params.id]);
    res.json({ message: 'Frais supprimés.' });
  }));

  // ---------- Côté étudiant ----------
  router.get('/fees/me', requireAuth, requireRole('etudiant'), asyncHandler(async (req, res) => {
    const rows = (await pool.query(
      `SELECT sf.*, f.label, f.due_date, f.academic_year FROM student_fees sf JOIN fees f ON f.id=sf.fee_id
       WHERE sf.student_id=$1 ORDER BY f.due_date NULLS LAST`, [req.user.id])).rows;
    const pays = (await pool.query(
      `SELECT id, student_fee_id, amount_fcfa, method, status, receipt_number, created_at, paid_at
       FROM payments WHERE student_id=$1 ORDER BY created_at DESC`, [req.user.id])).rows;
    res.json(rows.map((r) => ({
      id: r.id, label: r.label, academicYear: r.academic_year, amountDue: r.amount_due_fcfa, amountPaid: r.amount_paid_fcfa,
      remaining: r.amount_due_fcfa - r.amount_paid_fcfa, status: r.status, dueDate: r.due_date,
      overdue: !!r.due_date && r.status !== 'paye' && new Date(r.due_date) < new Date(),
      payments: pays.filter((p) => p.student_fee_id === r.id).map((p) => ({
        id: p.id, amount: p.amount_fcfa, method: p.method, status: p.status, receiptNumber: p.receipt_number, date: p.paid_at || p.created_at })),
    })));
  }));

  router.post('/payments/initiate', requireAuth, requireRole('etudiant'), asyncHandler(async (req, res) => {
    const { studentFeeId, method } = req.body;
    const amount = Number(req.body.amountFcfa);
    if (!studentFeeId || !Number.isInteger(amount) || amount <= 0) throw C.err(400, 'Montant invalide (entier positif en FCFA).');
    const sf = (await pool.query('SELECT * FROM student_fees WHERE id=$1 AND student_id=$2', [studentFeeId, req.user.id])).rows[0];
    if (!sf) throw C.err(404, 'Frais introuvable.');
    const pending = Number((await pool.query(
      `SELECT COALESCE(SUM(amount_fcfa),0) AS s FROM payments WHERE student_fee_id=$1 AND status='en_attente'`, [sf.id])).rows[0].s);
    const remaining = sf.amount_due_fcfa - sf.amount_paid_fcfa - pending;
    if (amount > remaining) throw C.err(400, `Montant supérieur au solde disponible (${Math.max(remaining, 0)} FCFA).`);
    const id = crypto.randomUUID();
    const ref = `UC-${Date.now()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const m = ['mobile_money', 'carte'].includes(method) ? method : 'mobile_money';
    await pool.query(
      `INSERT INTO payments (id, student_id, student_fee_id, amount_fcfa, method, provider, reference_externe, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,'en_attente')`,
      [id, req.user.id, sf.id, amount, m, process.env.PAYMENT_PROVIDER || (SANDBOX ? 'sandbox' : 'generic'), ref]);
    let paymentUrl = null;
    if (process.env.PAYSTACK_SECRET_KEY) {
      try {
        const info = (await pool.query(
          `SELECT u.email, s.matricule FROM users u LEFT JOIN students s ON s.user_id = u.id WHERE u.id = $1`, [req.user.id])).rows[0] || {};
        const r = await axios.post('https://api.paystack.co/transaction/initialize', {
          email: info.email || `${(info.matricule || req.user.id).toString().toLowerCase()}@uniconnect.app`,
          amount: amount * 100,
          currency: process.env.PAYSTACK_CURRENCY || 'XOF',
          reference: ref,
          callback_url: process.env.PAYSTACK_CALLBACK_URL || undefined,
        }, { headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` }, timeout: 15000 });
        paymentUrl = r.data && r.data.data ? r.data.data.authorization_url : null;
      } catch (e) { console.error('[Paystack] initialisation impossible :', e.response ? JSON.stringify(e.response.data) : e.message); }
    } else if (process.env.PAYMENT_PROVIDER_URL && process.env.PAYMENT_PROVIDER_KEY) {
      try {
        const r = await axios.post(process.env.PAYMENT_PROVIDER_URL, {
          reference: ref, amount, currency: 'XOF', description: 'Frais de scolarité UniConnect',
          callback_url: `${process.env.PUBLIC_URL || ''}/api/v1/payments/webhook`,
        }, { headers: { Authorization: `Bearer ${process.env.PAYMENT_PROVIDER_KEY}` }, timeout: 15000 });
        paymentUrl = r.data.payment_url || r.data.url || null;
      } catch (e) { console.error('[Paiement] Fournisseur indisponible :', e.message); }
    }
    res.status(201).json({ paymentId: id, reference: ref, amountFcfa: amount, paymentUrl, sandbox: SANDBOX,
      message: paymentUrl ? 'Redirection vers le paiement.' : 'Paiement initié. En attente de confirmation du fournisseur.' });
  }));

  /** Valide un paiement de façon atomique (une seule fois), crédite le solde et notifie. */
  async function settlePayment(reference, success, paidAmount) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const pay = (await client.query(`SELECT * FROM payments WHERE reference_externe=$1 FOR UPDATE`, [reference])).rows[0];
      if (!pay) { await client.query('ROLLBACK'); return { code: 404, message: 'Paiement inconnu.' }; }
      if (pay.status !== 'en_attente') { await client.query('ROLLBACK'); return { code: 200, message: 'Déjà traité.' }; }
      if (!success) {
        await client.query(`UPDATE payments SET status='echec' WHERE id=$1`, [pay.id]);
        await client.query('COMMIT'); return { code: 200, message: 'Échec enregistré.' };
      }
      if (paidAmount != null && Number(paidAmount) !== pay.amount_fcfa) {
        await client.query(`UPDATE payments SET status='echec', note='Montant reçu différent' WHERE id=$1`, [pay.id]);
        await client.query('COMMIT'); return { code: 409, message: 'Montant incohérent.' };
      }
      const seq = (await client.query(`SELECT nextval('receipt_seq') AS n`)).rows[0].n;
      const receipt = `RCU-${new Date().getFullYear()}-${String(seq).padStart(6, '0')}`;
      await client.query(`UPDATE payments SET status='reussi', receipt_number=$2, paid_at=now() WHERE id=$1`, [pay.id, receipt]);
      await client.query(
        `UPDATE student_fees SET amount_paid_fcfa=amount_paid_fcfa+$1,
         status=CASE WHEN amount_paid_fcfa+$1 >= amount_due_fcfa THEN 'paye' ELSE 'partiel' END WHERE id=$2`,
        [pay.amount_fcfa, pay.student_fee_id]);
      await client.query('COMMIT');
      await notifyUser(pay.student_id, 'payment_success', { amount: pay.amount_fcfa, receipt }, { paymentId: pay.id });
      return { code: 200, message: 'Paiement confirmé.' };
    } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; } finally { client.release(); }
  }
  C.settlePayment = settlePayment;

  /** Webhook : signature HMAC-SHA256 du corps brut (en-tête x-signature) obligatoire. */
  router.post('/payments/webhook', asyncHandler(async (req, res) => {
    // Paystack : signature HMAC-SHA512 du corps brut avec la clé secrète (en-tête x-paystack-signature)
    const psSig = req.headers['x-paystack-signature'];
    if (psSig && process.env.PAYSTACK_SECRET_KEY) {
      const exp = crypto.createHmac('sha512', process.env.PAYSTACK_SECRET_KEY).update(req.rawBody || Buffer.from('')).digest('hex');
      const pa = Buffer.from(String(psSig)); const pb = Buffer.from(exp);
      if (pa.length !== pb.length || !crypto.timingSafeEqual(pa, pb)) throw C.err(401, 'Signature invalide.');
      const ev = req.body || {};
      const data = ev.data || {};
      if (ev.event === 'charge.success' && data.reference) {
        await settlePayment(data.reference, true, Math.round(Number(data.amount) / 100));
      } else if (ev.event === 'charge.failed' && data.reference) {
        await settlePayment(data.reference, false, null);
      }
      return res.status(200).json({ message: 'ok' });
    }
    const secret = process.env.PAYMENT_WEBHOOK_SECRET;
    if (!secret) throw C.err(503, 'Webhook désactivé : PAYMENT_WEBHOOK_SECRET non configuré.');
    const sig = String(req.headers['x-signature'] || '');
    const expected = crypto.createHmac('sha256', secret).update(req.rawBody || Buffer.from('')).digest('hex');
    const a = Buffer.from(sig); const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw C.err(401, 'Signature invalide.');
    const { reference, status, amount } = req.body;
    if (!reference) throw C.err(400, 'reference manquante.');
    const r = await settlePayment(reference, ['success', 'reussi', 'paid'].includes(status), amount);
    res.status(r.code).json({ message: r.message });
  }));
  /** Bac à sable : simule la confirmation du fournisseur (désactivé hors PAYMENT_SANDBOX=true). */
  router.post('/payments/:id/simulate', requireAuth, requireRole('etudiant'), asyncHandler(async (req, res) => {
    if (!SANDBOX) throw C.err(403, 'Mode bac à sable désactivé.');
    const p = (await pool.query('SELECT reference_externe FROM payments WHERE id=$1 AND student_id=$2', [req.params.id, req.user.id])).rows[0];
    if (!p) throw C.err(404, 'Paiement introuvable.');
    const r = await settlePayment(p.reference_externe, req.body.success !== false, null);
    res.status(r.code).json({ message: r.message });
  }));

  // ---------- Reçus PDF ----------
  async function receiptPdf(paymentId, user) {
    const p = (await pool.query(
      `SELECT p.*, f.label, f.academic_year FROM payments p JOIN student_fees sf ON sf.id=p.student_fee_id
       JOIN fees f ON f.id=sf.fee_id WHERE p.id=$1 AND p.status='reussi'`, [paymentId])).rows[0];
    if (!p) throw C.err(404, 'Reçu introuvable.');
    if (user.role === 'etudiant' && p.student_id !== user.id) throw C.err(403, 'Accès refusé.');
    if (!['etudiant', 'comptabilite', 'admin', 'directeur', 'scolarite'].includes(user.role)) throw C.err(403, 'Accès refusé.');
    const who = await C.studentIdentity(p.student_id);
    const code = await C.issueCode('recu', p.student_id, p.academic_year, { receipt: p.receipt_number, amount: p.amount_fcfa });
    return C.pdfToBuffer(async (doc) => {
      await C.pdfHeader(doc, `RECU DE PAIEMENT N° ${p.receipt_number}`);
      doc.fontSize(12).fillColor('#000')
        .text(`Etudiant : ${who.full_name}`).text(`Matricule : ${who.matricule}`)
        .text(`Objet : ${p.label} (${p.academic_year})`).text(`Montant : ${p.amount_fcfa} FCFA`)
        .text(`Mode : ${p.method}`).text(`Date : ${new Date(p.paid_at || p.created_at).toLocaleString('fr-FR')}`);
      await C.pdfFooterQr(doc, code);
    });
  }
  router.get('/payments/:id/receipt', requireAuth, asyncHandler(async (req, res) => {
    const buf = await receiptPdf(req.params.id, req.user);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'inline; filename="recu.pdf"');
    res.send(buf);
  }));

  // ---------- Comptabilité ----------
  router.get('/accounting/dashboard', requireAuth, ACC_VIEW, asyncHandler(async (req, res) => {
    const t = (await pool.query(
      `SELECT COALESCE(SUM(amount_due_fcfa),0) AS due, COALESCE(SUM(amount_paid_fcfa),0) AS paid,
              COUNT(*) FILTER (WHERE sf.status<>'paye' AND f.due_date < CURRENT_DATE) AS overdue
       FROM student_fees sf JOIN fees f ON f.id=sf.fee_id`)).rows[0];
    const byProgram = (await pool.query(
      `SELECT COALESCE(p.name,'Sans filière') AS program, SUM(sf.amount_due_fcfa) AS due, SUM(sf.amount_paid_fcfa) AS paid
       FROM student_fees sf JOIN students s ON s.user_id=sf.student_id LEFT JOIN programs p ON p.id=s.program_id GROUP BY 1 ORDER BY 1`)).rows;
    const month = (await pool.query(
      `SELECT to_char(date_trunc('month', paid_at),'YYYY-MM') AS month, SUM(amount_fcfa) AS total FROM payments
       WHERE status='reussi' AND paid_at > now() - interval '12 months' GROUP BY 1 ORDER BY 1`)).rows;
    const due = Number(t.due), paid = Number(t.paid);
    res.json({ totalDue: due, totalPaid: paid, remaining: due - paid, recoveryRate: due ? Math.round((paid / due) * 1000) / 10 : 0,
      overdueCount: Number(t.overdue), byProgram, monthly: month });
  }));
  router.get('/accounting/debtors', requireAuth, ACC_VIEW, asyncHandler(async (req, res) => {
    res.json((await pool.query(
      `SELECT u.id AS student_id, u.full_name, u.phone, st.matricule, f.label, f.due_date,
              sf.amount_due_fcfa - sf.amount_paid_fcfa AS remaining, (f.due_date < CURRENT_DATE) AS overdue, sf.id AS student_fee_id
       FROM student_fees sf JOIN fees f ON f.id=sf.fee_id JOIN users u ON u.id=sf.student_id
       LEFT JOIN students st ON st.user_id=u.id WHERE sf.status<>'paye'
       ORDER BY overdue DESC, f.due_date NULLS LAST, u.full_name LIMIT 500`)).rows);
  }));
  router.get('/accounting/payments', requireAuth, ACC_VIEW, asyncHandler(async (req, res) => {
    res.json((await pool.query(
      `SELECT p.*, u.full_name, st.matricule FROM payments p JOIN users u ON u.id=p.student_id
       LEFT JOIN students st ON st.user_id=p.student_id WHERE p.status=COALESCE($1,p.status)
       ORDER BY p.created_at DESC LIMIT 300`, [req.query.status || null])).rows);
  }));
  /** Encaissement au guichet (espèces) : même circuit que le paiement en ligne. */
  router.post('/accounting/payments/cash', requireAuth, ACC, asyncHandler(async (req, res) => {
    const amount = Number(req.body.amountFcfa);
    const sf = (await pool.query('SELECT * FROM student_fees WHERE id=$1', [req.body.studentFeeId])).rows[0];
    if (!sf) throw C.err(404, 'Frais introuvable.');
    if (!Number.isInteger(amount) || amount <= 0 || amount > sf.amount_due_fcfa - sf.amount_paid_fcfa) throw C.err(400, 'Montant invalide ou supérieur au solde.');
    const id = crypto.randomUUID(); const ref = `CASH-${Date.now()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    await pool.query(
      `INSERT INTO payments (id, student_id, student_fee_id, amount_fcfa, method, provider, reference_externe, status, recorded_by, note)
       VALUES ($1,$2,$3,$4,'espece','guichet',$5,'en_attente',$6,$7)`,
      [id, sf.student_id, sf.id, amount, ref, req.user.id, req.body.note || null]);
    await settlePayment(ref, true, amount);
    await audit(req.user.id, 'cash_payment', 'payment', id, { amount }, req.ip);
    res.status(201).json({ id, message: 'Paiement en espèces enregistré.' });
  }));
  /** Rapprochement : confirmation ou rejet manuel d'un paiement resté en attente. */
  router.post('/accounting/payments/:id/reconcile', requireAuth, ACC, asyncHandler(async (req, res) => {
    const p = (await pool.query('SELECT reference_externe FROM payments WHERE id=$1', [req.params.id])).rows[0];
    if (!p) throw C.err(404, 'Paiement introuvable.');
    const r = await settlePayment(p.reference_externe, req.body.success === true, null);
    await audit(req.user.id, 'reconcile_payment', 'payment', req.params.id, req.body, req.ip);
    res.status(r.code).json({ message: r.message });
  }));
  router.get('/accounting/export/:type', requireAuth, ACC_VIEW, asyncHandler(async (req, res) => {
    const q = {
      payments: `SELECT p.created_at AS date, st.matricule, u.full_name AS etudiant, f.label AS objet, p.amount_fcfa AS montant,
                        p.method AS mode, p.status AS statut, p.receipt_number AS recu
                 FROM payments p JOIN users u ON u.id=p.student_id LEFT JOIN students st ON st.user_id=p.student_id
                 JOIN student_fees sf ON sf.id=p.student_fee_id JOIN fees f ON f.id=sf.fee_id ORDER BY p.created_at DESC`,
      balances: `SELECT st.matricule, u.full_name AS etudiant, f.label AS objet, f.due_date AS echeance, sf.amount_due_fcfa AS du,
                        sf.amount_paid_fcfa AS paye, sf.status AS statut
                 FROM student_fees sf JOIN fees f ON f.id=sf.fee_id JOIN users u ON u.id=sf.student_id
                 LEFT JOIN students st ON st.user_id=sf.student_id ORDER BY u.full_name`,
    }[req.params.type];
    if (!q) throw C.err(400, "Type d'export inconnu (payments | balances).");
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${req.params.type}.csv"`);
    res.send(toCsv((await pool.query(q)).rows));
  }));
};

// ============================== MODULE : comms ==============================
const mod_comms = (d, C) => {
  const { router, pool, crypto, requireAuth, requireRole, asyncHandler, audit, notifyUser, sendSms,
    getIo, currentAcademicYear } = d;
  const POSTERS = requireRole('scolarite', 'admin', 'directeur', 'enseignant');
  const MODS = ['scolarite', 'admin'];

  // ---------- Annonces ciblées ----------
  async function recipients(a) {
    if (a.course_id) return (await C.roster(a.course_id, currentAcademicYear())).map((r) => r.id);
    const ids = new Set();
    const hasAudience = a.faculty_id || a.program_id || a.level_id || a.group_name;
    if (hasAudience || a.target_role === 'etudiant') {
      const p = []; let w = 'u.is_active';
      if (a.faculty_id) { p.push(a.faculty_id); w += ` AND pr.faculty_id=$${p.length}`; }
      if (a.program_id) { p.push(a.program_id); w += ` AND s.program_id=$${p.length}`; }
      if (a.level_id) { p.push(a.level_id); w += ` AND s.level_id=$${p.length}`; }
      if (a.group_name) { p.push(a.group_name); w += ` AND s.group_name=$${p.length}`; }
      (await pool.query(
        `SELECT s.user_id FROM students s JOIN users u ON u.id=s.user_id LEFT JOIN programs pr ON pr.id=s.program_id WHERE ${w}`, p))
        .rows.forEach((r) => ids.add(r.user_id));
    }
    if (!hasAudience && a.target_role !== 'etudiant') {
      const r = a.target_role
        ? await pool.query('SELECT id FROM users WHERE role=$1 AND is_active', [a.target_role])
        : await pool.query('SELECT id FROM users WHERE is_active');
      r.rows.forEach((x) => ids.add(x.id));
    }
    return [...ids];
  }

  router.post('/announcements', requireAuth, POSTERS, asyncHandler(async (req, res) => {
    const b = req.body;
    if (!b.title || !b.body) throw C.err(400, 'title et body requis.');
    if (req.user.role === 'enseignant') {
      if (!b.courseId) throw C.err(403, "Un enseignant publie uniquement pour l'un de ses cours (courseId).");
      await C.ownCourse(b.courseId, req.user);
    }
    const id = crypto.randomUUID();
    await pool.query(
      `INSERT INTO announcements (id, author_id, title, body, target_role, faculty_id, program_id, level_id, group_name,
        course_id, is_urgent, send_sms, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
      [id, req.user.id, b.title, b.body, b.targetRole || null, b.facultyId || null, b.programId || null, b.levelId || null,
        b.groupName || null, b.courseId || null, !!b.isUrgent, !!b.isUrgent && b.sendSms !== false, b.expiresAt || null]);
    const a = (await pool.query('SELECT * FROM announcements WHERE id=$1', [id])).rows[0];
    res.status(201).json({ id, message: 'Annonce publiée.' });
    // Diffusion en arrière-plan (notification + SMS pour les messages urgents)
    setImmediate(async () => {
      try {
        const ids = await recipients(a);
        for (const uid of ids) {
          await notifyUser(uid, 'announcement', { title: b.title, body: b.body }, { announcementId: id });
          if (a.is_urgent && a.send_sms) {
            const ph = (await pool.query('SELECT phone FROM users WHERE id=$1', [uid])).rows[0]?.phone;
            if (ph) await sendSms(ph, `${b.title} : ${String(b.body).slice(0, 120)}`);
          }
        }
        getIo().emit('announcement', { id, title: b.title });
      } catch (e) { console.error('[Annonce]', e.message); }
    });
  }));

  router.get('/announcements', requireAuth, asyncHandler(async (req, res) => {
    const base = `SELECT a.*, u.full_name AS author_name FROM announcements a LEFT JOIN users u ON u.id=a.author_id
      WHERE (a.expires_at IS NULL OR a.expires_at>now())`;
    let rows;
    if (req.user.role === 'etudiant') {
      const st = (await pool.query(
        `SELECT s.program_id, s.level_id, s.group_name, pr.faculty_id FROM students s
         LEFT JOIN programs pr ON pr.id=s.program_id WHERE s.user_id=$1`, [req.user.id])).rows[0] || {};
      const courses = await C.studentCourseIds(req.user.id, currentAcademicYear());
      rows = (await pool.query(
        `${base} AND (a.target_role IS NULL OR a.target_role='etudiant')
         AND (a.faculty_id IS NULL OR a.faculty_id=$1) AND (a.program_id IS NULL OR a.program_id=$2)
         AND (a.level_id IS NULL OR a.level_id=$3) AND (a.group_name IS NULL OR a.group_name=$4)
         AND (a.course_id IS NULL OR a.course_id = ANY($5)) ORDER BY a.is_urgent DESC, a.created_at DESC LIMIT 50`,
        [st.faculty_id || null, st.program_id || null, st.level_id || null, st.group_name || null, courses])).rows;
    } else if (req.user.role === 'enseignant') {
      rows = (await pool.query(
        `${base} AND (a.target_role IS NULL OR a.target_role='enseignant')
         AND a.faculty_id IS NULL AND a.program_id IS NULL AND a.level_id IS NULL
         AND (a.course_id IS NULL OR a.course_id IN (SELECT id FROM courses WHERE teacher_id=$1) OR a.author_id=$1)
         ORDER BY a.is_urgent DESC, a.created_at DESC LIMIT 50`, [req.user.id])).rows;
    } else {
      rows = (await pool.query(`${base} ORDER BY a.is_urgent DESC, a.created_at DESC LIMIT 100`)).rows;
    }
    res.json(rows.map((a) => ({ id: a.id, title: a.title, body: a.body, authorName: a.author_name, isUrgent: a.is_urgent,
      createdAt: a.created_at, expiresAt: a.expires_at })));
  }));
  router.delete('/announcements/:id', requireAuth, POSTERS, asyncHandler(async (req, res) => {
    const a = (await pool.query('SELECT author_id FROM announcements WHERE id=$1', [req.params.id])).rows[0];
    if (!a) throw C.err(404, 'Annonce introuvable.');
    if (a.author_id !== req.user.id && !MODS.includes(req.user.role)) throw C.err(403, 'Accès refusé.');
    await pool.query('DELETE FROM announcements WHERE id=$1', [req.params.id]);
    res.json({ message: 'Annonce supprimée.' });
  }));

  // ---------- Messagerie directe ----------
  /** Un étudiant écrit à ses enseignants / à la scolarité ; un enseignant à ses étudiants / à la scolarité. */
  async function canMessage(me, target) {
    if (me.id === target.id) return false;
    if (C.STAFF.includes(me.role) || C.STAFF.includes(target.role)) return true;
    const [stu, tea] = me.role === 'etudiant' ? [me, target] : [target, me];
    if (stu.role !== 'etudiant' || tea.role !== 'enseignant') return false;
    const ids = await C.studentCourseIds(stu.id, currentAcademicYear());
    return (await pool.query('SELECT 1 FROM courses WHERE id = ANY($1) AND teacher_id=$2', [ids, tea.id])).rowCount > 0;
  }
  router.get('/contacts', requireAuth, asyncHandler(async (req, res) => {
    let rows;
    if (req.user.role === 'etudiant') {
      const ids = await C.studentCourseIds(req.user.id, currentAcademicYear());
      rows = (await pool.query(
        `SELECT DISTINCT u.id, u.full_name, u.role FROM users u WHERE u.is_active AND
         (u.role='scolarite' OR u.id IN (SELECT teacher_id FROM courses WHERE id = ANY($1) AND teacher_id IS NOT NULL))
         ORDER BY u.full_name`, [ids])).rows;
    } else if (req.user.role === 'enseignant') {
      rows = (await pool.query(
        `SELECT DISTINCT u.id, u.full_name, u.role FROM users u WHERE u.is_active AND
         (u.role='scolarite' OR u.id IN (SELECT e.student_id FROM enrollments e JOIN courses c ON c.id=e.course_id
            WHERE c.teacher_id=$1 AND e.status='inscrit')) ORDER BY u.full_name`, [req.user.id])).rows;
    } else {
      rows = (await pool.query(`SELECT id, full_name, role FROM users WHERE is_active AND id<>$1 ORDER BY full_name LIMIT 300`, [req.user.id])).rows;
    }
    res.json(rows.map((r) => ({ id: r.id, fullName: r.full_name, role: r.role })));
  }));

  router.post('/messages', requireAuth, asyncHandler(async (req, res) => {
    const { recipientId, courseId } = req.body;
    const body = String(req.body.body || '').trim();
    if (!body || body.length > 2000) throw C.err(400, 'Message vide ou trop long (2000 max).');
    const id = crypto.randomUUID();
    if (courseId) { // forum de classe
      const c = (await pool.query('SELECT * FROM courses WHERE id=$1', [courseId])).rows[0];
      if (!c) throw C.err(404, 'Cours introuvable.');
      const ok = req.user.role === 'etudiant' ? await C.studentInCourse(req.user.id, courseId, currentAcademicYear())
        : req.user.role === 'enseignant' ? c.teacher_id === req.user.id : MODS.includes(req.user.role);
      if (!ok) throw C.err(403, 'Accès au forum refusé.');
      await pool.query('INSERT INTO messages (id, sender_id, course_id, body) VALUES ($1,$2,$3,$4)', [id, req.user.id, courseId, body]);
      getIo().to(`course:${courseId}`).emit('forum', { id, courseId });
      return res.status(201).json({ id });
    }
    if (!recipientId) throw C.err(400, 'recipientId ou courseId requis.');
    const target = (await pool.query('SELECT id, role, full_name FROM users WHERE id=$1 AND is_active', [recipientId])).rows[0];
    if (!target) throw C.err(404, 'Destinataire introuvable.');
    if (!(await canMessage({ id: req.user.id, role: req.user.role }, target))) throw C.err(403, 'Vous ne pouvez pas écrire à cette personne.');
    await pool.query('INSERT INTO messages (id, sender_id, recipient_id, body) VALUES ($1,$2,$3,$4)', [id, req.user.id, recipientId, body]);
    await notifyUser(recipientId, 'message_new', { sender: req.user.name, text: body.slice(0, 80) }, { senderId: req.user.id });
    getIo().to(`user:${recipientId}`).emit('message', { id, senderId: req.user.id });
    res.status(201).json({ id });
  }));
  router.get('/messages/threads', requireAuth, asyncHandler(async (req, res) => {
    const rows = (await pool.query(
      `SELECT DISTINCT ON (t.other) t.other, t.body, t.created_at, t.sender_id, u.full_name,
         (SELECT COUNT(*) FROM messages x WHERE x.sender_id=t.other AND x.recipient_id=$1 AND x.read_at IS NULL) AS unread
       FROM (SELECT CASE WHEN sender_id=$1 THEN recipient_id ELSE sender_id END AS other, body, created_at, sender_id
             FROM messages WHERE recipient_id IS NOT NULL AND (sender_id=$1 OR recipient_id=$1)) t
       JOIN users u ON u.id=t.other ORDER BY t.other, t.created_at DESC`, [req.user.id])).rows;
    res.json(rows.map((r) => ({ userId: r.other, fullName: r.full_name, lastMessage: r.body, lastAt: r.created_at, unread: Number(r.unread) }))
      .sort((a, b) => new Date(b.lastAt) - new Date(a.lastAt)));
  }));
  router.get('/messages/with/:userId', requireAuth, asyncHandler(async (req, res) => {
    await pool.query('UPDATE messages SET read_at=now() WHERE sender_id=$1 AND recipient_id=$2 AND read_at IS NULL', [req.params.userId, req.user.id]);
    const rows = (await pool.query(
      `SELECT id, sender_id, body, created_at FROM messages WHERE recipient_id IS NOT NULL AND
       ((sender_id=$1 AND recipient_id=$2) OR (sender_id=$2 AND recipient_id=$1)) ORDER BY created_at DESC LIMIT 200`,
      [req.user.id, req.params.userId])).rows;
    res.json(rows.reverse().map((m) => ({ id: m.id, mine: m.sender_id === req.user.id, body: m.body, createdAt: m.created_at })));
  }));

  // ---------- Forum de classe modéré ----------
  router.get('/courses/:id/forum', requireAuth, asyncHandler(async (req, res) => {
    const c = (await pool.query('SELECT * FROM courses WHERE id=$1', [req.params.id])).rows[0];
    if (!c) throw C.err(404, 'Cours introuvable.');
    const ok = req.user.role === 'etudiant' ? await C.studentInCourse(req.user.id, c.id, currentAcademicYear())
      : req.user.role === 'enseignant' ? c.teacher_id === req.user.id : true;
    if (!ok) throw C.err(403, 'Accès au forum refusé.');
    const mod = MODS.includes(req.user.role) || req.user.role === 'enseignant';
    const rows = (await pool.query(
      `SELECT m.id, m.body, m.created_at, m.hidden, m.sender_id, u.full_name, u.role,
        (SELECT COUNT(*) FROM message_reports r WHERE r.message_id=m.id) AS reports
       FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.course_id=$1 AND ($2 OR m.hidden=false)
       ORDER BY m.created_at DESC LIMIT 100`, [c.id, mod])).rows;
    res.json(rows.reverse().map((m) => ({ id: m.id, author: m.full_name, role: m.role, mine: m.sender_id === req.user.id,
      body: m.hidden ? '[message masqué par la modération]' : m.body, hidden: m.hidden, reports: Number(m.reports), createdAt: m.created_at })));
  }));
  router.post('/messages/:id/report', requireAuth, asyncHandler(async (req, res) => {
    await pool.query(
      'INSERT INTO message_reports (id, message_id, reporter_id, reason) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING',
      [crypto.randomUUID(), req.params.id, req.user.id, req.body.reason || null]);
    res.json({ message: 'Signalement envoyé à la modération.' });
  }));
  router.patch('/messages/:id/hide', requireAuth, requireRole('enseignant', 'scolarite', 'admin'), asyncHandler(async (req, res) => {
    const m = (await pool.query('SELECT m.*, c.teacher_id FROM messages m JOIN courses c ON c.id=m.course_id WHERE m.id=$1', [req.params.id])).rows[0];
    if (!m) throw C.err(404, 'Message introuvable.');
    if (req.user.role === 'enseignant' && m.teacher_id !== req.user.id) throw C.err(403, 'Accès refusé.');
    await pool.query('UPDATE messages SET hidden=$2 WHERE id=$1', [m.id, req.body.hidden !== false]);
    await audit(req.user.id, 'moderate_message', 'message', m.id, { hidden: req.body.hidden !== false }, req.ip);
    res.json({ message: 'Modération appliquée.' });
  }));
};

// ============================== MODULE : registration ==============================
const mod_registration = (d, C) => {
  const { router, app, pool, crypto, requireAuth, requireRole, asyncHandler, audit, notifyUser, upload,
    sendSms, sendEmail, authLimiter, normalizePhone, normalizeEmail, currentAcademicYear } = d;
  const SCOL = requireRole('scolarite', 'admin');
  const REQUIRED_DOCS = ['acte_naissance', 'diplome', 'photo', 'piece_identite'];
  const DOC_TYPES = [...REQUIRED_DOCS, 'autre'];
  const STATUS_FR = { recu: 'reçu', en_examen: "en cours d'examen", pieces_manquantes: 'pièces manquantes', accepte: 'accepté', refuse: 'refusé' };

  // ---------- Pré-inscription publique ----------
  router.get('/public/programs', asyncHandler(async (req, res) => {
    const programs = (await pool.query('SELECT id, name, code FROM programs ORDER BY name')).rows;
    const levels = (await pool.query('SELECT id, program_id, name, year_order FROM levels ORDER BY year_order')).rows;
    res.json({ requiredDocuments: REQUIRED_DOCS, programs: programs.map((p) => ({ ...p, levels: levels.filter((l) => l.program_id === p.id) })) });
  }));
  router.post('/public/applications', authLimiter, asyncHandler(async (req, res) => {
    const { fullName, phone, email, birthDate, programId, levelId } = req.body;
    if (!fullName || !phone || !programId) throw C.err(400, 'Nom, téléphone et filière requis.');
    const code = `PRE-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const id = crypto.randomUUID();
    await pool.query(
      `INSERT INTO applications (id, code, full_name, phone, email, birth_date, program_id, level_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [id, code, fullName, normalizePhone(phone), email ? normalizeEmail(email) : null, birthDate || null, programId, levelId || null]);
    await sendSms(normalizePhone(phone), `UniConnect : dossier ${code} reçu. Déposez vos pièces et suivez son état avec ce code.`);
    res.status(201).json({ code, requiredDocuments: REQUIRED_DOCS, message: 'Dossier créé. Déposez maintenant vos pièces justificatives.' });
  }));
  async function loadApplication(code, phone) {
    const a = (await pool.query('SELECT * FROM applications WHERE code=$1', [String(code).toUpperCase()])).rows[0];
    if (!a || normalizePhone(phone || '') !== a.phone) throw C.err(404, 'Dossier introuvable (vérifiez le code et le téléphone).');
    return a;
  }
  router.post('/public/applications/:code/documents', authLimiter, upload.single('file'), asyncHandler(async (req, res) => {
    const a = await loadApplication(req.params.code, req.body.phone || req.query.phone);
    if (['accepte', 'refuse'].includes(a.status)) throw C.err(400, 'Dossier clôturé.');
    if (!DOC_TYPES.includes(req.body.docType)) throw C.err(400, `docType invalide (${DOC_TYPES.join(', ')}).`);
    if (!req.file || !/^(application\/pdf|image\/(jpeg|png|webp))$/.test(req.file.mimetype)) throw C.err(400, 'Fichier PDF ou image requis.');
    const count = Number((await pool.query('SELECT COUNT(*) FROM application_documents WHERE application_id=$1', [a.id])).rows[0].count);
    if (count >= 12) throw C.err(400, 'Nombre maximal de pièces atteint.');
    const fileId = await C.saveFile(req.file, null);
    if (req.body.docType !== 'autre') {
      await pool.query('DELETE FROM application_documents WHERE application_id=$1 AND doc_type=$2', [a.id, req.body.docType]);
    }
    await pool.query('INSERT INTO application_documents (id, application_id, doc_type, file_id) VALUES ($1,$2,$3,$4)', [crypto.randomUUID(), a.id, req.body.docType, fileId]);
    if (a.status === 'pieces_manquantes') await pool.query(`UPDATE applications SET status='en_examen', updated_at=now() WHERE id=$1`, [a.id]);
    res.status(201).json({ message: 'Pièce enregistrée.' });
  }));
  router.get('/public/applications/:code', authLimiter, asyncHandler(async (req, res) => {
    const a = await loadApplication(req.params.code, req.query.phone);
    const docs = (await pool.query('SELECT doc_type FROM application_documents WHERE application_id=$1', [a.id])).rows.map((r) => r.doc_type);
    res.json({ code: a.code, status: a.status, statusLabel: STATUS_FR[a.status], note: a.note, documents: docs,
      missing: REQUIRED_DOCS.filter((x) => !docs.includes(x)) });
  }));

  // ---------- Traitement par la scolarité ----------
  router.get('/admin/applications', requireAuth, SCOL, asyncHandler(async (req, res) => {
    res.json((await pool.query(
      `SELECT a.*, p.name AS program_name, l.name AS level_name,
         (SELECT COUNT(*) FROM application_documents d WHERE d.application_id=a.id) AS documents
       FROM applications a LEFT JOIN programs p ON p.id=a.program_id LEFT JOIN levels l ON l.id=a.level_id
       WHERE a.status=COALESCE($1,a.status) ORDER BY a.created_at DESC LIMIT 300`, [req.query.status || null])).rows);
  }));
  router.get('/admin/applications/:id', requireAuth, SCOL, asyncHandler(async (req, res) => {
    const a = (await pool.query('SELECT * FROM applications WHERE id=$1', [req.params.id])).rows[0];
    if (!a) throw C.err(404, 'Dossier introuvable.');
    const docs = (await pool.query('SELECT * FROM application_documents WHERE application_id=$1 ORDER BY created_at', [a.id])).rows;
    res.json({ ...a, documents: docs.map((x) => ({ id: x.id, type: x.doc_type, url: C.fileUrl(x.file_id) })) });
  }));
  async function acceptApplication(a, byUser) {
    const docs = (await pool.query('SELECT doc_type FROM application_documents WHERE application_id=$1', [a.id])).rows.map((r) => r.doc_type);
    const missing = REQUIRED_DOCS.filter((x) => !docs.includes(x));
    if (missing.length) throw C.err(400, `Pièces manquantes : ${missing.join(', ')}.`);
    const prog = a.program_id ? (await pool.query('SELECT code FROM programs WHERE id=$1', [a.program_id])).rows[0] : null;
    const seq = (await pool.query(`SELECT nextval('matricule_seq') AS n`)).rows[0].n;
    const matricule = `${(prog?.code || 'UC').toUpperCase()}${String(new Date().getFullYear()).slice(2)}${seq}`;
    const uid = crypto.randomUUID();
    try {
      await pool.query(`INSERT INTO users (id, full_name, phone, email, role) VALUES ($1,$2,$3,$4,'etudiant')`, [uid, a.full_name, a.phone, a.email]);
    } catch (e) { if (e.code === '23505') throw C.err(409, 'Téléphone ou e-mail déjà associé à un compte.'); throw e; }
    await pool.query(
      `INSERT INTO students (user_id, matricule, program_id, level_id, academic_year, birth_date) VALUES ($1,$2,$3,$4,$5,$6)`,
      [uid, matricule, a.program_id, a.level_id, currentAcademicYear(), a.birth_date]);
    await app.locals.syncStudent(uid);
    await pool.query(`UPDATE applications SET status='accepte', student_user_id=$2, updated_at=now() WHERE id=$1`, [a.id, uid]);
    await sendSms(a.phone, `UniConnect : félicitations, votre admission est validée. Matricule : ${matricule}. Ouvrez l'application et activez votre compte avec ce matricule et ce numéro.`);
    if (a.email) await sendEmail({ to: a.email, subject: 'Admission validée', text: `Votre matricule : ${matricule}. Activez votre compte dans l'application UniConnect.` });
    await audit(byUser, 'accept_application', 'application', a.id, { matricule }, null);
    return matricule;
  }
  router.patch('/admin/applications/:id', requireAuth, SCOL, asyncHandler(async (req, res) => {
    const a = (await pool.query('SELECT * FROM applications WHERE id=$1', [req.params.id])).rows[0];
    if (!a) throw C.err(404, 'Dossier introuvable.');
    if (a.status === 'accepte') throw C.err(400, 'Dossier déjà accepté.');
    const { status, note } = req.body;
    if (!['en_examen', 'pieces_manquantes', 'accepte', 'refuse'].includes(status)) throw C.err(400, 'Statut invalide.');
    if (['pieces_manquantes', 'refuse'].includes(status) && !note) throw C.err(400, 'Une note (pièces demandées ou motif) est obligatoire.');
    let matricule = null;
    if (status === 'accepte') matricule = await acceptApplication(a, req.user.id);
    else await pool.query('UPDATE applications SET status=$2, note=$3, updated_at=now() WHERE id=$1', [a.id, status, note || null]);
    if (status !== 'accepte') {
      await sendSms(a.phone, `UniConnect : dossier ${a.code} ${STATUS_FR[status]}.${note ? ' ' + note : ''}`);
    }
    await audit(req.user.id, 'application_status', 'application', a.id, { status }, req.ip);
    res.json({ message: status === 'accepte' ? `Admission validée. Matricule ${matricule}.` : 'Dossier mis à jour.', matricule });
  }));

  // ---------- Réinscription annuelle ----------
  function nextYear() {
    const [a, b] = currentAcademicYear().split('-').map(Number);
    return `${a + 1}-${b + 1}`;
  }
  async function validatedCourses(studentId) {
    const sum = await C.computeSummary(studentId);
    const ok = new Map();
    for (const c of sum.courses) ok.set(c.courseId, ok.get(c.courseId) || c.validated);
    return ok;
  }
  async function options(studentId) {
    const st = (await pool.query('SELECT * FROM students WHERE user_id=$1', [studentId])).rows[0];
    if (!st || !st.level_id) throw C.err(400, 'Niveau actuel inconnu : contactez la scolarité.');
    const level = (await pool.query('SELECT * FROM levels WHERE id=$1', [st.level_id])).rows[0];
    const ok = await validatedCourses(studentId);
    const levelCourses = (await pool.query('SELECT * FROM courses WHERE level_id=$1', [level.id])).rows;
    const earned = levelCourses.filter((c) => ok.get(c.id)).reduce((s, c) => s + Number(c.credits), 0);
    const ratio = Number(await C.getSetting('pass_credit_ratio', '0.8'));
    const required = Math.ceil(Number(level.total_credits) * ratio);
    const next = (await pool.query('SELECT * FROM levels WHERE program_id=$1 AND year_order=$2', [level.program_id, level.year_order + 1])).rows[0];
    const promoted = earned >= required && !!next;
    const target = promoted ? next : level;
    const carry = promoted ? levelCourses.filter((c) => !ok.get(c.id)) : [];
    const courses = (await pool.query('SELECT * FROM courses WHERE level_id=$1 ORDER BY semester, code', [target.id])).rows.map((c) => ({
      id: c.id, code: c.code, title: c.title, credits: Number(c.credits), semester: c.semester, optional: !!c.is_optional,
      mandatory: !c.is_optional, carryOver: false, blocked: !!c.prerequisite_course_id && !ok.get(c.prerequisite_course_id),
    }));
    for (const c of carry) {
      courses.push({ id: c.id, code: c.code, title: c.title, credits: Number(c.credits), semester: c.semester,
        optional: false, mandatory: true, carryOver: true, blocked: false });
    }
    return { student: st, level, target, promoted, earned, required, courses, maxCredits: Number(target.max_credits) };
  }
  router.get('/enrollment/options', requireAuth, requireRole('etudiant'), asyncHandler(async (req, res) => {
    const o = await options(req.user.id);
    const year = nextYear();
    const pending = (await pool.query('SELECT status, note FROM reenrollment_requests WHERE student_id=$1 AND academic_year=$2', [req.user.id, year])).rows[0] || null;
    res.json({ academicYear: year, currentLevel: o.level.name, suggestedLevelId: o.target.id, suggestedLevel: o.target.name,
      promoted: o.promoted, creditsEarned: o.earned, creditsRequired: o.required, maxCredits: o.maxCredits, courses: o.courses, request: pending });
  }));
  router.post('/enrollment/reregister', requireAuth, requireRole('etudiant'), asyncHandler(async (req, res) => {
    const o = await options(req.user.id);
    if (await C.isBlockedForUnpaid(req.user.id)) throw C.err(403, 'Régularisez vos frais avant de vous réinscrire.');
    const levelId = req.body.levelId || o.target.id;
    if (levelId !== o.target.id) throw C.err(400, `Votre situation académique correspond au niveau ${o.target.name}.`);
    const chosen = new Set(req.body.courseIds || []);
    for (const c of o.courses) if (c.mandatory) chosen.add(c.id);
    const list = o.courses.filter((c) => chosen.has(c.id));
    if (list.length !== chosen.size) throw C.err(400, 'Un des cours choisis ne fait pas partie de votre niveau.');
    const blocked = list.find((c) => c.blocked);
    if (blocked) throw C.err(400, `Prérequis non validé pour ${blocked.code}.`);
    const credits = list.reduce((s, c) => s + c.credits, 0);
    if (credits > o.maxCredits) throw C.err(400, `Total de crédits (${credits}) supérieur au maximum autorisé (${o.maxCredits}).`);
    const year = nextYear();
    const r = await pool.query(
      `INSERT INTO reenrollment_requests (id, student_id, academic_year, level_id, course_ids) VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (student_id, academic_year) DO UPDATE SET level_id=$4, course_ids=$5, status='en_attente', note=NULL
       WHERE reenrollment_requests.status<>'valide' RETURNING id`, [crypto.randomUUID(), req.user.id, year, levelId, [...chosen]]);
    if (!r.rowCount) throw C.err(409, 'Réinscription déjà validée.');
    res.status(201).json({ message: 'Demande de réinscription envoyée à la scolarité.', credits });
  }));
  router.get('/admin/reenrollments', requireAuth, SCOL, asyncHandler(async (req, res) => {
    res.json((await pool.query(
      `SELECT r.*, u.full_name, s.matricule, l.name AS level_name, cardinality(r.course_ids) AS courses FROM reenrollment_requests r
       JOIN users u ON u.id=r.student_id LEFT JOIN students s ON s.user_id=r.student_id LEFT JOIN levels l ON l.id=r.level_id
       WHERE r.status=COALESCE($1,r.status) ORDER BY r.created_at DESC`, [req.query.status || 'en_attente'])).rows);
  }));
  router.patch('/admin/reenrollments/:id', requireAuth, SCOL, asyncHandler(async (req, res) => {
    const r = (await pool.query('SELECT * FROM reenrollment_requests WHERE id=$1', [req.params.id])).rows[0];
    if (!r) throw C.err(404, 'Demande introuvable.');
    const { status, note } = req.body;
    if (!['valide', 'refuse'].includes(status)) throw C.err(400, 'status invalide.');
    if (status === 'refuse' && !note) throw C.err(400, 'Motif obligatoire.');
    if (status === 'valide') {
      await pool.query('UPDATE students SET level_id=$2, academic_year=$3 WHERE user_id=$1', [r.student_id, r.level_id, r.academic_year]);
      for (const cid of r.course_ids) {
        await pool.query(
          `INSERT INTO enrollments (id, student_id, course_id, academic_year) VALUES ($1,$2,$3,$4)
           ON CONFLICT (student_id, course_id, academic_year) DO UPDATE SET status='inscrit'`,
          [crypto.randomUUID(), r.student_id, cid, r.academic_year]);
      }
      await app.locals.syncStudent(r.student_id);
    }
    await pool.query('UPDATE reenrollment_requests SET status=$2, note=$3, handled_at=now() WHERE id=$1', [r.id, status, note || null]);
    await notifyUser(r.student_id, 'reenroll_update', { year: r.academic_year, status: status === 'valide' ? 'validée' : 'refusée' }, { requestId: r.id });
    await audit(req.user.id, 'reenrollment', 'reenrollment', r.id, { status }, req.ip);
    res.json({ message: 'Réinscription traitée.' });
  }));
};

// ============================== MODULE : campus ==============================
const mod_campus = (d, C) => {
  const { router, app, pool, crypto, requireAuth, requireRole, asyncHandler, audit, notifyUser,
    currentAcademicYear } = d;
  const SCOL = requireRole('scolarite', 'admin');
  const DOC_TITLES = { attestation_scolarite: 'ATTESTATION DE SCOLARITE', certificat: 'CERTIFICAT', releve_notes: 'RELEVE DE NOTES', autre: 'DOCUMENT' };

  // ---------- Demandes de documents ----------
  router.post('/documents/request', requireAuth, requireRole('etudiant'), asyncHandler(async (req, res) => {
    const { type } = req.body;
    if (!DOC_TITLES[type]) throw C.err(400, 'Type invalide.');
    const open = await pool.query(`SELECT 1 FROM document_requests WHERE student_id=$1 AND type=$2 AND status IN ('en_attente','en_cours')`, [req.user.id, type]);
    if (open.rowCount) throw C.err(409, 'Une demande de ce type est déjà en cours.');
    const id = crypto.randomUUID();
    await pool.query('INSERT INTO document_requests (id, student_id, type, academic_year) VALUES ($1,$2,$3,$4)', [id, req.user.id, type, currentAcademicYear()]);
    res.status(201).json({ id, message: 'Demande enregistrée.' });
  }));
  router.get('/documents/me', requireAuth, requireRole('etudiant'), asyncHandler(async (req, res) => {
    const rows = (await pool.query('SELECT * FROM document_requests WHERE student_id=$1 ORDER BY created_at DESC', [req.user.id])).rows;
    res.json(rows.map((x) => ({ id: x.id, type: x.type, status: x.status, fileUrl: x.file_url, motifRefus: x.motif_refus, createdAt: x.created_at })));
  }));
  router.get('/admin/documents', requireAuth, SCOL, asyncHandler(async (req, res) => {
    res.json((await pool.query(
      `SELECT r.*, u.full_name, s.matricule FROM document_requests r JOIN users u ON u.id=r.student_id
       LEFT JOIN students s ON s.user_id=r.student_id WHERE r.status=COALESCE($1,r.status) ORDER BY r.created_at DESC LIMIT 300`,
      [req.query.status || null])).rows);
  }));

  async function documentPdf(studentId, type, year) {
    const who = await C.studentIdentity(studentId);
    if (type === 'releve_notes') return C.transcriptPdf(studentId, null, null);
    const code = await C.issueCode(type, studentId, year, {});
    return C.pdfToBuffer(async (doc) => {
      await C.pdfHeader(doc, DOC_TITLES[type]);
      doc.fontSize(12).fillColor('#000').moveDown(2);
      if (type === 'attestation_scolarite') {
        doc.text(`Le/la soussigne(e) atteste que ${who.full_name}, matricule ${who.matricule}, est regulierement inscrit(e) en ${who.level || ''} ${who.program || ''} pour l'annee academique ${year}.`, { align: 'justify' });
      } else {
        doc.text(`Il est certifie que ${who.full_name}, matricule ${who.matricule}, est etudiant(e) de notre etablissement (${who.program || '-'}, ${who.level || '-'}) pour l'annee ${year}.`, { align: 'justify' });
      }
      doc.moveDown(2).text(`Fait le ${new Date().toLocaleDateString('fr-FR')}.`);
      await C.pdfFooterQr(doc, code);
    });
  }
  /** Traitement : génération automatique du PDF avec QR de vérification, ou refus motivé. */
  router.patch('/documents/:id', requireAuth, SCOL, asyncHandler(async (req, res) => {
    const r = (await pool.query('SELECT * FROM document_requests WHERE id=$1', [req.params.id])).rows[0];
    if (!r) throw C.err(404, 'Demande introuvable.');
    const { status, motifRefus } = req.body;
    if (status === 'refuse') {
      if (!motifRefus) throw C.err(400, 'Motif obligatoire.');
      await pool.query(`UPDATE document_requests SET status='refuse', motif_refus=$2, updated_at=now() WHERE id=$1`, [r.id, motifRefus]);
    } else if (status === 'en_cours') {
      await pool.query(`UPDATE document_requests SET status='en_cours', updated_at=now() WHERE id=$1`, [r.id]);
    } else if (status === 'pret') {
      const buf = await documentPdf(r.student_id, r.type, r.academic_year || currentAcademicYear());
      const fileId = await C.savePdfBuffer(buf, `${r.type}.pdf`, r.student_id);
      await pool.query(`UPDATE document_requests SET status='pret', file_url=$2, updated_at=now() WHERE id=$1`, [r.id, C.fileUrl(fileId)]);
      await notifyUser(r.student_id, 'document_ready', { type: r.type }, { requestId: r.id });
    } else throw C.err(400, 'status invalide (en_cours | pret | refuse).');
    await audit(req.user.id, 'document_request', 'document_request', r.id, { status }, req.ip);
    res.json({ message: 'Demande traitée.' });
  }));

  // ---------- Vérification publique (QR des documents et cartes) ----------
  const check = async (code) => {
    const r = (await pool.query(
      `SELECT i.*, u.full_name, s.matricule FROM issued_documents i JOIN users u ON u.id=i.student_id
       LEFT JOIN students s ON s.user_id=i.student_id WHERE i.code=$1`, [String(code).toUpperCase()])).rows[0];
    return r ? { valid: true, type: r.type, student: r.full_name, matricule: r.matricule, academicYear: r.academic_year, issuedAt: r.created_at } : { valid: false };
  };
  router.get('/verify/:code', asyncHandler(async (req, res) => res.json(await check(req.params.code))));
  app.get('/verify/:code', asyncHandler(async (req, res) => {
    const v = await check(req.params.code);
    const esc = (s) => String(s ?? '').replace(/[<>&"]/g, '');
    res.type('html').send(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verification</title><body style="font-family:sans-serif;max-width:480px;margin:40px auto;padding:0 16px">
<h2>${v.valid ? '✅ Document authentique' : '❌ Document introuvable'}</h2>
${v.valid ? `<p><b>${esc(v.student)}</b> (${esc(v.matricule)})<br>Type : ${esc(v.type)}<br>Année : ${esc(v.academicYear)}<br>Émis le ${new Date(v.issuedAt).toLocaleDateString('fr-FR')}</p>` : "<p>Ce code ne correspond à aucun document émis par l'établissement.</p>"}</body>`);
  }));

  // ---------- Carte étudiante numérique ----------
  router.get('/students/me/card', requireAuth, requireRole('etudiant'), asyncHandler(async (req, res) => {
    const who = await C.studentIdentity(req.user.id);
    const st = (await pool.query('SELECT photo_url FROM students WHERE user_id=$1', [req.user.id])).rows[0];
    const year = currentAcademicYear();
    let doc = (await pool.query(`SELECT code FROM issued_documents WHERE student_id=$1 AND type='carte' AND academic_year=$2`, [req.user.id, year])).rows[0];
    if (!doc) doc = { code: await C.issueCode('carte', req.user.id, year, {}) };
    res.json({ fullName: who.full_name, matricule: who.matricule, program: who.program, level: who.level, academicYear: year,
      photoUrl: st?.photo_url || null, code: doc.code, qrPayload: C.verifyUrl(doc.code) });
  }));

  // ---------- Bibliothèque ----------
  router.get('/library/items', requireAuth, asyncHandler(async (req, res) => {
    const q = `%${req.query.q || ''}%`;
    res.json((await pool.query(
      `SELECT * FROM library_items WHERE title ILIKE $1 OR author ILIKE $1 OR category ILIKE $1 OR isbn ILIKE $1 ORDER BY title LIMIT 100`, [q])).rows);
  }));
  router.post('/library/items', requireAuth, SCOL, asyncHandler(async (req, res) => {
    const b = req.body;
    if (!b.title) throw C.err(400, 'Titre requis.');
    const n = Math.max(1, Number(b.copies) || 1);
    const id = crypto.randomUUID();
    await pool.query('INSERT INTO library_items (id, title, author, isbn, category, copies_total, copies_available) VALUES ($1,$2,$3,$4,$5,$6,$6)',
      [id, b.title, b.author || null, b.isbn || null, b.category || null, n]);
    res.status(201).json({ id });
  }));
  router.post('/library/reserve', requireAuth, requireRole('etudiant', 'enseignant'), asyncHandler(async (req, res) => {
    const it = (await pool.query('SELECT * FROM library_items WHERE id=$1', [req.body.itemId])).rows[0];
    if (!it) throw C.err(404, 'Ouvrage introuvable.');
    const dup = await pool.query(`SELECT 1 FROM library_reservations WHERE item_id=$1 AND user_id=$2 AND status='active'`, [it.id, req.user.id]);
    if (dup.rowCount) throw C.err(409, 'Déjà réservé.');
    await pool.query('INSERT INTO library_reservations (id, item_id, user_id) VALUES ($1,$2,$3)', [crypto.randomUUID(), it.id, req.user.id]);
    res.status(201).json({ message: "Réservation enregistrée. Passez à la bibliothèque pour retirer l'ouvrage." });
  }));
  router.delete('/library/reservations/:id', requireAuth, asyncHandler(async (req, res) => {
    await pool.query(`UPDATE library_reservations SET status='annulee' WHERE id=$1 AND user_id=$2`, [req.params.id, req.user.id]);
    res.json({ message: 'Réservation annulée.' });
  }));
  router.get('/library/me', requireAuth, asyncHandler(async (req, res) => {
    const loans = (await pool.query(
      `SELECT l.*, i.title, i.author, (l.returned_at IS NULL AND l.due_at < now()) AS overdue FROM library_loans l
       JOIN library_items i ON i.id=l.item_id WHERE l.user_id=$1 ORDER BY l.borrowed_at DESC LIMIT 50`, [req.user.id])).rows;
    const reservations = (await pool.query(
      `SELECT r.id, r.created_at, i.title, i.author FROM library_reservations r JOIN library_items i ON i.id=r.item_id
       WHERE r.user_id=$1 AND r.status='active'`, [req.user.id])).rows;
    res.json({ loans, reservations });
  }));
  router.get('/library/reservations', requireAuth, SCOL, asyncHandler(async (req, res) => {
    res.json((await pool.query(
      `SELECT r.id, r.item_id, r.user_id, r.created_at, i.title, u.full_name, s.matricule FROM library_reservations r
       JOIN library_items i ON i.id=r.item_id JOIN users u ON u.id=r.user_id LEFT JOIN students s ON s.user_id=r.user_id
       WHERE r.status='active' ORDER BY r.created_at`)).rows);
  }));
  /** Prêt au guichet : par identifiant utilisateur ou matricule. */
  router.post('/library/loans', requireAuth, SCOL, asyncHandler(async (req, res) => {
    const { itemId, userId, matricule } = req.body;
    const u = userId ? { id: userId } : (await pool.query('SELECT user_id AS id FROM students WHERE matricule=$1', [String(matricule || '').toUpperCase()])).rows[0];
    if (!u) throw C.err(404, 'Emprunteur introuvable.');
    const late = await pool.query('SELECT 1 FROM library_loans WHERE user_id=$1 AND returned_at IS NULL AND due_at<now()', [u.id]);
    if (late.rowCount) throw C.err(409, 'Emprunteur avec livre(s) en retard.');
    const upd = await pool.query('UPDATE library_items SET copies_available=copies_available-1 WHERE id=$1 AND copies_available>0 RETURNING id', [itemId]);
    if (!upd.rowCount) throw C.err(409, 'Aucun exemplaire disponible.');
    const days = Number(await C.getSetting('loan_days', '14'));
    await pool.query(`INSERT INTO library_loans (id, item_id, user_id, due_at) VALUES ($1,$2,$3, now() + ($4 || ' days')::interval)`, [crypto.randomUUID(), itemId, u.id, String(days)]);
    await pool.query(`UPDATE library_reservations SET status='honoree' WHERE item_id=$1 AND user_id=$2 AND status='active'`, [itemId, u.id]);
    res.status(201).json({ message: `Prêt enregistré (${days} jours).` });
  }));
  router.post('/library/loans/:id/return', requireAuth, SCOL, asyncHandler(async (req, res) => {
    const l = (await pool.query('UPDATE library_loans SET returned_at=now() WHERE id=$1 AND returned_at IS NULL RETURNING item_id', [req.params.id])).rows[0];
    if (!l) throw C.err(404, 'Prêt introuvable ou déjà rendu.');
    await pool.query('UPDATE library_items SET copies_available=copies_available+1 WHERE id=$1', [l.item_id]);
    res.json({ message: 'Retour enregistré.' });
  }));
  router.get('/library/loans', requireAuth, SCOL, asyncHandler(async (req, res) => {
    res.json((await pool.query(
      `SELECT l.*, i.title, u.full_name, s.matricule, (l.due_at<now()) AS overdue FROM library_loans l
       JOIN library_items i ON i.id=l.item_id JOIN users u ON u.id=l.user_id LEFT JOIN students s ON s.user_id=l.user_id
       WHERE l.returned_at IS NULL ORDER BY l.due_at`)).rows);
  }));

  // ---------- Examens et convocations ----------
  router.post('/admin/exams', requireAuth, SCOL, asyncHandler(async (req, res) => {
    const { courseId, examDate, startTime, durationMinutes, roomIds, semester, kind } = req.body;
    if (!courseId || !examDate || !startTime || !Array.isArray(roomIds) || !roomIds.length) throw C.err(400, 'courseId, examDate, startTime et roomIds requis.');
    const year = req.body.academicYear || currentAcademicYear();
    const rooms = (await pool.query('SELECT * FROM rooms WHERE id = ANY($1)', [roomIds])).rows;
    const roster = await C.roster(courseId, year);
    const capacity = rooms.reduce((s, r) => s + (r.capacity || 0), 0);
    if (capacity < roster.length) throw C.err(400, `Capacité insuffisante (${capacity} places pour ${roster.length} étudiants).`);
    const dur = Number(durationMinutes) || 120;
    const clash = await pool.query(
      `SELECT 1 FROM exam_seats es JOIN exams e ON e.id=es.exam_id WHERE es.room_id = ANY($1) AND e.exam_date=$2
       AND e.start_time < ($3::time + ($4 || ' minutes')::interval) AND (e.start_time + (e.duration_minutes || ' minutes')::interval) > $3::time LIMIT 1`,
      [roomIds, examDate, startTime, String(dur)]);
    if (clash.rowCount) throw C.err(409, 'Une des salles est déjà utilisée sur ce créneau.');
    const id = crypto.randomUUID();
    await pool.query('INSERT INTO exams (id, course_id, academic_year, semester, kind, exam_date, start_time, duration_minutes) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
      [id, courseId, year, semester || 1, kind || 'examen', examDate, startTime, dur]);
    let i = 0;
    for (const room of rooms) {
      for (let seat = 1; seat <= (room.capacity || 0) && i < roster.length; seat += 1, i += 1) {
        await pool.query('INSERT INTO exam_seats (exam_id, student_id, room_id, seat_number) VALUES ($1,$2,$3,$4)', [id, roster[i].id, room.id, seat]);
      }
    }
    const course = (await pool.query('SELECT title FROM courses WHERE id=$1', [courseId])).rows[0];
    const roomOf = new Map(rooms.map((r) => [r.id, r.name]));
    const seats = (await pool.query('SELECT * FROM exam_seats WHERE exam_id=$1', [id])).rows;
    for (const s of seats) {
      await notifyUser(s.student_id, 'exam_convocation', { course: course.title, date: new Date(examDate).toLocaleDateString('fr-FR'), time: String(startTime).slice(0, 5), room: roomOf.get(s.room_id), seat: s.seat_number }, { examId: id });
    }
    await audit(req.user.id, 'create_exam', 'exam', id, req.body, req.ip);
    res.status(201).json({ id, seated: seats.length });
  }));
  router.get('/admin/exams', requireAuth, requireRole('scolarite', 'admin', 'directeur'), asyncHandler(async (req, res) => {
    res.json((await pool.query(
      `SELECT e.*, c.code, c.title, (SELECT COUNT(*) FROM exam_seats s WHERE s.exam_id=e.id) AS students FROM exams e
       JOIN courses c ON c.id=e.course_id ORDER BY e.exam_date DESC, e.start_time`)).rows);
  }));
  router.delete('/admin/exams/:id', requireAuth, SCOL, asyncHandler(async (req, res) => {
    await pool.query('DELETE FROM exams WHERE id=$1', [req.params.id]);
    res.json({ message: 'Examen supprimé.' });
  }));
  router.get('/exams/me', requireAuth, requireRole('etudiant'), asyncHandler(async (req, res) => {
    if (await C.isBlockedForUnpaid(req.user.id)) throw C.err(403, 'Convocations suspendues : régularisez vos frais de scolarité.');
    res.json((await pool.query(
      `SELECT e.id, e.exam_date, e.start_time, e.duration_minutes, e.kind, c.code, c.title, r.name AS room, r.building, es.seat_number
       FROM exam_seats es JOIN exams e ON e.id=es.exam_id JOIN courses c ON c.id=e.course_id LEFT JOIN rooms r ON r.id=es.room_id
       WHERE es.student_id=$1 AND e.exam_date >= CURRENT_DATE - 1 ORDER BY e.exam_date, e.start_time`, [req.user.id])).rows);
  }));
  router.get('/exams/:id/convocation.pdf', requireAuth, requireRole('etudiant'), asyncHandler(async (req, res) => {
    if (await C.isBlockedForUnpaid(req.user.id)) throw C.err(403, 'Convocation suspendue : régularisez vos frais.');
    const e = (await pool.query(
      `SELECT e.*, c.title, r.name AS room, es.seat_number FROM exam_seats es JOIN exams e ON e.id=es.exam_id
       JOIN courses c ON c.id=e.course_id LEFT JOIN rooms r ON r.id=es.room_id WHERE e.id=$1 AND es.student_id=$2`, [req.params.id, req.user.id])).rows[0];
    if (!e) throw C.err(404, 'Convocation introuvable.');
    const who = await C.studentIdentity(req.user.id);
    const code = await C.issueCode('convocation', req.user.id, e.academic_year, { examId: e.id });
    const buf = await C.pdfToBuffer(async (doc) => {
      await C.pdfHeader(doc, "CONVOCATION D'EXAMEN");
      doc.fontSize(12).fillColor('#000').text(`Etudiant : ${who.full_name} (${who.matricule})`)
        .text(`Epreuve : ${e.title}`).text(`Date : ${new Date(e.exam_date).toLocaleDateString('fr-FR')} a ${String(e.start_time).slice(0, 5)} (${e.duration_minutes} min)`)
        .text(`Salle : ${e.room || '-'}   Place n° ${e.seat_number}`).moveDown().text("Presentez-vous muni de votre carte d'etudiant.");
      await C.pdfFooterQr(doc, code);
    });
    res.setHeader('Content-Type', 'application/pdf');
    res.send(buf);
  }));

  // ---------- Stages et emplois ----------
  router.get('/internships', requireAuth, asyncHandler(async (req, res) => {
    const staff = C.STAFF.includes(req.user.role);
    res.json((await pool.query(
      `SELECT i.*, (SELECT COUNT(*) FROM internship_applications a WHERE a.internship_id=i.id) AS applicants,
         EXISTS(SELECT 1 FROM internship_applications a WHERE a.internship_id=i.id AND a.student_id=$1) AS applied
       FROM internships i WHERE ($2::boolean OR i.status='publie') AND (i.deadline IS NULL OR i.deadline >= CURRENT_DATE OR $2::boolean)
       ORDER BY i.created_at DESC LIMIT 100`, [req.user.id, staff])).rows);
  }));
  router.post('/internships', requireAuth, requireRole('scolarite', 'admin', 'enseignant', 'directeur'), asyncHandler(async (req, res) => {
    const b = req.body;
    if (!b.title || !b.company) throw C.err(400, 'Titre et entreprise requis.');
    const direct = ['scolarite', 'admin'].includes(req.user.role);
    const id = crypto.randomUUID();
    await pool.query('INSERT INTO internships (id, title, company, description, location, deadline, status, posted_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
      [id, b.title, b.company, b.description || null, b.location || null, b.deadline || null, direct ? 'publie' : 'en_attente', req.user.id]);
    res.status(201).json({ id, message: direct ? 'Offre publiée.' : 'Offre soumise à validation de la scolarité.' });
  }));
  router.patch('/internships/:id', requireAuth, SCOL, asyncHandler(async (req, res) => {
    if (!['publie', 'refuse'].includes(req.body.status)) throw C.err(400, 'status invalide.');
    await pool.query('UPDATE internships SET status=$2 WHERE id=$1', [req.params.id, req.body.status]);
    res.json({ message: 'Offre mise à jour.' });
  }));
  router.post('/internships/:id/apply', requireAuth, requireRole('etudiant'), asyncHandler(async (req, res) => {
    const i = (await pool.query(`SELECT 1 FROM internships WHERE id=$1 AND status='publie'`, [req.params.id])).rows[0];
    if (!i) throw C.err(404, 'Offre introuvable.');
    await pool.query('INSERT INTO internship_applications (internship_id, student_id, message) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING', [req.params.id, req.user.id, req.body.message || null]);
    res.status(201).json({ message: 'Candidature envoyée.' });
  }));
  router.get('/internships/:id/applicants', requireAuth, SCOL, asyncHandler(async (req, res) => {
    res.json((await pool.query(
      `SELECT a.*, u.full_name, u.phone, u.email, s.matricule FROM internship_applications a JOIN users u ON u.id=a.student_id
       LEFT JOIN students s ON s.user_id=a.student_id WHERE a.internship_id=$1 ORDER BY a.created_at`, [req.params.id])).rows);
  }));
};

// ============================== MODULE : reports ==============================
const mod_reports = (d, C) => {
  const { router, pool, requireAuth, requireRole, asyncHandler } = d;
  const VIEW = requireRole('admin', 'scolarite', 'directeur');

  router.get('/admin/stats', requireAuth, VIEW, asyncHandler(async (req, res) => {
    const one = async (sql) => Number((await pool.query(sql)).rows[0].count);
    const counts = {
      students: await one(`SELECT COUNT(*) FROM users WHERE role='etudiant' AND is_active`),
      teachers: await one(`SELECT COUNT(*) FROM users WHERE role='enseignant' AND is_active`),
      pendingApplications: await one(`SELECT COUNT(*) FROM applications WHERE status IN ('recu','en_examen')`),
      pendingReenrollments: await one(`SELECT COUNT(*) FROM reenrollment_requests WHERE status='en_attente'`),
      pendingClaims: await one(`SELECT COUNT(*) FROM grade_claims WHERE status='en_attente'`),
      pendingDocuments: await one(`SELECT COUNT(*) FROM document_requests WHERE status IN ('en_attente','en_cours')`),
      pendingJustifications: await one(`SELECT COUNT(*) FROM absence_justifications WHERE status='en_attente'`),
      gradesToPublish: await one(`SELECT COUNT(DISTINCT course_id) FROM grades WHERE status='soumis'`),
      pendingInternships: await one(`SELECT COUNT(*) FROM internships WHERE status='en_attente'`),
    };
    const enrollment = (await pool.query(
      `SELECT COALESCE(p.name,'-') AS program, COALESCE(l.name,'-') AS level, COUNT(*) AS students
       FROM students s JOIN users u ON u.id=s.user_id AND u.is_active LEFT JOIN programs p ON p.id=s.program_id
       LEFT JOIN levels l ON l.id=s.level_id GROUP BY 1,2 ORDER BY 1,2`)).rows;
    const passRates = (await pool.query(
      `WITH a AS (SELECT course_id, student_id, SUM(score/NULLIF(max_score,0)*20*coefficient)/NULLIF(SUM(coefficient),0) AS avg
                  FROM grades WHERE status='publie' GROUP BY 1,2)
       SELECT c.code, c.title, COUNT(*) AS students, COUNT(*) FILTER (WHERE a.avg>=10) AS passed,
              ROUND(AVG(a.avg)::numeric,2) AS average, ROUND(100.0*COUNT(*) FILTER (WHERE a.avg>=10)/COUNT(*),1) AS pass_rate
       FROM a JOIN courses c ON c.id=a.course_id GROUP BY c.code, c.title ORDER BY c.code`)).rows;
    const attendance = (await pool.query(
      `WITH held AS (SELECT id, course_id FROM attendance_sessions WHERE status='fermee' OR expires_at<now()),
            n AS (SELECT course_id, COUNT(*) AS sessions FROM held GROUP BY 1),
            p AS (SELECT h.course_id, COUNT(*) AS marks FROM attendances a JOIN held h ON h.id=a.session_id GROUP BY 1)
       SELECT c.code, c.title, n.sessions, COALESCE(p.marks,0) AS marks FROM n JOIN courses c ON c.id=n.course_id
       LEFT JOIN p ON p.course_id=n.course_id ORDER BY c.code`)).rows;
    const fin = (await pool.query(`SELECT COALESCE(SUM(amount_due_fcfa),0) AS due, COALESCE(SUM(amount_paid_fcfa),0) AS paid FROM student_fees`)).rows[0];
    res.json({ counts, enrollment, passRates, attendance, finance: { due: Number(fin.due), paid: Number(fin.paid),
      recoveryRate: Number(fin.due) ? Math.round((Number(fin.paid) / Number(fin.due)) * 1000) / 10 : 0 } });
  }));

  router.get('/admin/audit', requireAuth, requireRole('admin', 'directeur'), asyncHandler(async (req, res) => {
    const p = []; let w = '1=1';
    if (req.query.action) { p.push(`%${req.query.action}%`); w += ` AND a.action ILIKE $${p.length}`; }
    if (req.query.userId) { p.push(req.query.userId); w += ` AND a.user_id=$${p.length}`; }
    if (req.query.from) { p.push(req.query.from); w += ` AND a.created_at >= $${p.length}`; }
    const limit = Math.min(Number(req.query.limit) || 100, 500);
    res.json((await pool.query(
      `SELECT a.id, a.action, a.entity_type, a.entity_id, a.details, a.ip, a.created_at, u.full_name, u.role
       FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id WHERE ${w} ORDER BY a.created_at DESC LIMIT ${limit}`, p)).rows);
  }));

  router.get('/admin/export/:type', requireAuth, VIEW, asyncHandler(async (req, res) => {
    const q = {
      students: `SELECT s.matricule, u.full_name, u.phone, u.email, p.name AS filiere, l.name AS niveau, s.group_name AS groupe, s.academic_year AS annee
                 FROM students s JOIN users u ON u.id=s.user_id LEFT JOIN programs p ON p.id=s.program_id LEFT JOIN levels l ON l.id=s.level_id ORDER BY u.full_name`,
      grades: `SELECT s.matricule, u.full_name, c.code, g.evaluation_name, g.score, g.max_score, g.coefficient, g.academic_year, g.semester, g.status
               FROM grades g JOIN users u ON u.id=g.student_id LEFT JOIN students s ON s.user_id=g.student_id JOIN courses c ON c.id=g.course_id
               ORDER BY c.code, u.full_name`,
      attendance: `SELECT s.matricule, u.full_name, c.code, sess.started_at AS seance, a.method FROM attendances a
                   JOIN attendance_sessions sess ON sess.id=a.session_id JOIN courses c ON c.id=sess.course_id
                   JOIN users u ON u.id=a.student_id LEFT JOIN students s ON s.user_id=a.student_id ORDER BY sess.started_at DESC`,
    }[req.params.type];
    if (!q) throw C.err(400, 'Type inconnu (students | grades | attendance).');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${req.params.type}.csv"`);
    res.send(C.toCsv((await pool.query(q)).rows));
  }));
};

// ============================== MODULE : jobs ==============================
/** Tâches périodiques : clôture des séances, expiration des paiements, relances, retards de prêt. */
const mod_jobs = (d, C) => {
  const { pool, notifyUser } = d;
  async function every10min() {
    const expired = (await pool.query(
      `UPDATE attendance_sessions SET status='fermee', closed_at=now() WHERE status='ouverte' AND expires_at<now() RETURNING course_id`)).rows;
    for (const c of new Set(expired.map((r) => r.course_id))) await C.checkAbsenceAlerts(c);
    await pool.query(`UPDATE payments SET status='echec', note='Expiré (24 h sans confirmation)' WHERE status='en_attente' AND created_at < now() - interval '24 hours'`);
  }
  async function hourly() {
    const due = (await pool.query(
      `SELECT sf.id, sf.student_id, f.label, f.due_date, sf.amount_due_fcfa-sf.amount_paid_fcfa AS remaining
       FROM student_fees sf JOIN fees f ON f.id=sf.fee_id
       WHERE sf.status<>'paye' AND f.due_date BETWEEN CURRENT_DATE AND CURRENT_DATE + 3`)).rows;
    for (const r of due) {
      const ins = await pool.query(`INSERT INTO reminders_sent (student_fee_id, kind, day) VALUES ($1,'due',$2) ON CONFLICT DO NOTHING RETURNING 1`, [r.id, r.due_date]);
      if (ins.rowCount) await notifyUser(r.student_id, 'payment_reminder', { label: r.label, amount: r.remaining, date: new Date(r.due_date).toLocaleDateString('fr-FR') }, { studentFeeId: r.id });
    }
    const late = (await pool.query(
      `SELECT sf.id, sf.student_id, f.label, f.due_date, sf.amount_due_fcfa-sf.amount_paid_fcfa AS remaining
       FROM student_fees sf JOIN fees f ON f.id=sf.fee_id WHERE sf.status<>'paye' AND f.due_date < CURRENT_DATE`)).rows;
    for (const r of late) {
      const ins = await pool.query(`INSERT INTO reminders_sent (student_fee_id, kind, day) VALUES ($1,'overdue',date_trunc('week', CURRENT_DATE)::date) ON CONFLICT DO NOTHING RETURNING 1`, [r.id]);
      if (ins.rowCount) await notifyUser(r.student_id, 'payment_overdue', { label: r.label, amount: r.remaining, date: new Date(r.due_date).toLocaleDateString('fr-FR') }, { studentFeeId: r.id });
    }
    const loans = (await pool.query(
      `SELECT l.id, l.user_id, l.due_at, i.title FROM library_loans l JOIN library_items i ON i.id=l.item_id WHERE l.returned_at IS NULL AND l.due_at < now()`)).rows;
    for (const l of loans) {
      const ins = await pool.query(`INSERT INTO reminders_sent (student_fee_id, kind, day) VALUES ($1,'loan',date_trunc('week', CURRENT_DATE)::date) ON CONFLICT DO NOTHING RETURNING 1`, [l.id]);
      if (ins.rowCount) await notifyUser(l.user_id, 'library_overdue', { title: l.title, date: new Date(l.due_at).toLocaleDateString('fr-FR') }, { loanId: l.id });
    }
  }
  C.runJobs = async () => { await every10min(); await hourly(); };
  if (process.env.DISABLE_JOBS === 'true') return;
  const safe = (fn) => () => fn().catch((e) => console.error('[Job]', e.message));
  setTimeout(safe(C.runJobs), 30 * 1000).unref();
  setInterval(safe(every10min), 10 * 60 * 1000).unref();
  setInterval(safe(hourly), 60 * 60 * 1000).unref();
};

// ============================== CHARGEUR DES MODULES ==============================
function mountModules(d) {
  const { pool, crypto } = d;
  const C = {};
  C.STAFF = ['scolarite', 'comptabilite', 'directeur', 'admin'];
  C.err = (status, message) => Object.assign(new Error(message), { status });

  // ---------- Paramètres de l'établissement ----------
  C.getSetting = async (key, def) => {
    const r = await pool.query('SELECT value FROM settings WHERE key = $1', [key]);
    return r.rows[0] ? r.rows[0].value : def;
  };

  // ---------- Fichiers (disque local ; utiliser un volume persistant en production) ----------
  const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(__dirname, '..', 'uploads');
  const insertFile = async (id, ownerId, name, mime, size, p) =>
    pool.query(
      'INSERT INTO files (id, owner_id, original_name, mime, size, path) VALUES ($1,$2,$3,$4,$5,$6)',
      [id, ownerId || null, name, mime, size, p],
    );
  /** Écrit les octets : Supabase Storage si configuré (persistant), sinon disque local. */
  const storePut = async (id, ext, buffer, mime) => {
    if (SUPABASE.enabled) {
      const name = `${id}${ext}`;
      await axios.post(`${SUPABASE.url}/storage/v1/object/${SUPABASE.bucket}/${name}`, buffer, {
        headers: sbHeaders({ 'Content-Type': mime || 'application/octet-stream', 'x-upsert': 'true' }),
        maxBodyLength: Infinity, maxContentLength: Infinity, timeout: 60000,
      });
      return `supabase:${name}`;
    }
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
    const p = path.join(UPLOAD_DIR, id + ext);
    fs.writeFileSync(p, buffer);
    return p;
  };
  /** Relit les octets d'un fichier enregistré (Supabase ou disque). */
  C.storeGet = async (stored) => {
    if (String(stored).startsWith('supabase:')) {
      if (!SUPABASE.enabled) throw C.err(503, 'Stockage Supabase non configuré.');
      const name = String(stored).slice('supabase:'.length);
      try {
        const r = await axios.get(`${SUPABASE.url}/storage/v1/object/authenticated/${SUPABASE.bucket}/${name}`, {
          responseType: 'arraybuffer', headers: sbHeaders(), timeout: 60000,
        });
        return Buffer.from(r.data);
      } catch (e) { throw C.err(404, 'Fichier introuvable.'); }
    }
    if (!fs.existsSync(stored)) throw C.err(404, 'Fichier introuvable.');
    return fs.readFileSync(stored);
  };
  C.saveFile = async (file, ownerId) => {
    if (!file) return null;
    const id = crypto.randomUUID();
    const ext = path.extname(file.originalname || '').replace(/[^.a-z0-9]/gi, '').slice(0, 8);
    const p = await storePut(id, ext, file.buffer, file.mimetype);
    await insertFile(id, ownerId, file.originalname, file.mimetype, file.size, p);
    return id;
  };
  C.savePdfBuffer = async (buffer, name, ownerId) => {
    const id = crypto.randomUUID();
    const p = await storePut(id, '.pdf', buffer, 'application/pdf');
    await insertFile(id, ownerId, name, 'application/pdf', buffer.length, p);
    return id;
  };
  C.fileUrl = (id) => (id ? `/api/v1/files/${id}` : null);

  // ---------- Cours d'un étudiant / effectif d'un cours ----------
  C.studentCourseIds = async (studentId, year) => {
    const e = await pool.query(
      `SELECT course_id FROM enrollments WHERE student_id=$1 AND academic_year=$2 AND status='inscrit'`,
      [studentId, year],
    );
    if (e.rows.length) return e.rows.map((r) => r.course_id);
    const s = (await pool.query('SELECT level_id FROM students WHERE user_id=$1', [studentId])).rows[0];
    if (!s || !s.level_id) return [];
    return (await pool.query('SELECT id FROM courses WHERE level_id=$1', [s.level_id])).rows.map((r) => r.id);
  };
  C.roster = async (courseId, year) => {
    const r = await pool.query(
      `SELECT u.id, u.full_name, s.matricule, s.group_name
       FROM enrollments e JOIN users u ON u.id = e.student_id
       LEFT JOIN students s ON s.user_id = u.id
       WHERE e.course_id=$1 AND e.academic_year=$2 AND e.status='inscrit' AND u.is_active
       ORDER BY u.full_name`,
      [courseId, year],
    );
    if (r.rows.length) return r.rows;
    return (
      await pool.query(
        `SELECT u.id, u.full_name, s.matricule, s.group_name
         FROM courses c JOIN students s ON s.level_id = c.level_id
         JOIN users u ON u.id = s.user_id
         WHERE c.id=$1 AND u.is_active ORDER BY u.full_name`,
        [courseId],
      )
    ).rows;
  };
  /** Vérifie qu'un enseignant est bien responsable du cours (scolarité/admin passent toujours). */
  C.ownCourse = async (courseId, user) => {
    const c = (await pool.query('SELECT * FROM courses WHERE id=$1', [courseId])).rows[0];
    if (!c) throw C.err(404, 'Cours introuvable.');
    if (user.role === 'enseignant' && c.teacher_id !== user.id) {
      throw C.err(403, "Vous n'êtes pas responsable de ce cours.");
    }
    if (user.role !== 'enseignant' && !['scolarite', 'admin'].includes(user.role)) {
      throw C.err(403, 'Accès refusé.');
    }
    return c;
  };
  C.studentInCourse = async (studentId, courseId, year) => {
    const ids = await C.studentCourseIds(studentId, year);
    return ids.includes(courseId);
  };

  // ---------- Règle de blocage en cas d'impayé (paramétrable) ----------
  C.isBlockedForUnpaid = async (studentId) => {
    if ((await C.getSetting('block_if_unpaid', 'false')) !== 'true') return false;
    const r = await pool.query(
      `SELECT 1 FROM student_fees sf JOIN fees f ON f.id = sf.fee_id
       WHERE sf.student_id=$1 AND sf.status <> 'paye' AND f.due_date < CURRENT_DATE LIMIT 1`,
      [studentId],
    );
    return r.rowCount > 0;
  };

  // ---------- Moyennes, crédits, mentions, décision (système LMD) ----------
  C.mention = (avg) =>
    avg >= 16 ? 'Très bien' : avg >= 14 ? 'Bien' : avg >= 12 ? 'Assez bien' : avg >= 10 ? 'Passable' : 'Insuffisant';
  C.computeSummary = async (studentId, year, semester) => {
    const params = [studentId];
    let filter = '';
    if (year) { params.push(year); filter += ` AND g.academic_year = $${params.length}`; }
    if (semester) { params.push(semester); filter += ` AND g.semester = $${params.length}`; }
    const rows = (
      await pool.query(
        `SELECT g.*, c.code, c.title, c.credits FROM grades g JOIN courses c ON c.id = g.course_id
         WHERE g.student_id=$1 AND g.status='publie' ${filter}
         ORDER BY g.academic_year, g.semester, c.code`,
        params,
      )
    ).rows;
    const byCourse = new Map();
    for (const g of rows) {
      const k = `${g.academic_year}|${g.semester}|${g.course_id}`;
      if (!byCourse.has(k)) {
        byCourse.set(k, {
          courseId: g.course_id, code: g.code, title: g.title, credits: Number(g.credits),
          academicYear: g.academic_year, semester: g.semester, sum: 0, coef: 0, evaluations: [],
        });
      }
      const c = byCourse.get(k);
      const coef = Number(g.coefficient) || 1;
      const on20 = (Number(g.score) / Number(g.max_score)) * 20;
      c.sum += on20 * coef;
      c.coef += coef;
      c.evaluations.push({
        id: g.id, name: g.evaluation_name, score: Number(g.score), maxScore: Number(g.max_score),
        coefficient: coef, publishedAt: g.published_at,
      });
    }
    const courses = [...byCourse.values()].map((c) => {
      const average = c.coef ? Math.round((c.sum / c.coef) * 100) / 100 : 0;
      return { ...c, sum: undefined, coef: undefined, average, validated: average >= 10 };
    });
    const sems = new Map();
    for (const c of courses) {
      const k = `${c.academicYear}|${c.semester}`;
      if (!sems.has(k)) sems.set(k, { academicYear: c.academicYear, semester: c.semester, w: 0, s: 0, credits: 0, earned: 0, n: 0, plain: 0 });
      const s = sems.get(k);
      s.n += 1; s.plain += c.average;
      s.w += c.credits; s.s += c.average * c.credits;
      s.credits += c.credits; if (c.validated) s.earned += c.credits;
    }
    const passRatio = Number(await C.getSetting('pass_credit_ratio', '0.8'));
    const semesters = [...sems.values()].map((s) => {
      const average = s.w > 0 ? s.s / s.w : s.n ? s.plain / s.n : 0;
      const avg = Math.round(average * 100) / 100;
      return {
        academicYear: s.academicYear, semester: s.semester, average: avg, mention: C.mention(avg),
        creditsTotal: s.credits, creditsEarned: s.earned,
        decision: avg >= 10 || (s.credits > 0 && s.earned >= passRatio * s.credits) ? 'Admis' : 'Ajourné',
      };
    });
    return { courses, semesters };
  };

  // Types de notifications supplémentaires (traduites côté serveur)
  Object.assign(d.NOTIF_I18N, {
    payment_reminder: {
      fr: { title: 'Échéance proche', body: '{label} : {amount} FCFA à régler avant le {date}.' },
      en: { title: 'Payment due soon', body: '{label}: {amount} FCFA due before {date}.' },
    },
    payment_overdue: {
      fr: { title: 'Paiement en retard', body: '{label} : {amount} FCFA en retard depuis le {date}.' },
      en: { title: 'Payment overdue', body: '{label}: {amount} FCFA overdue since {date}.' },
    },
    assignment_new: {
      fr: { title: 'Nouveau devoir', body: '{course} : {title} (à rendre le {date}).' },
      en: { title: 'New assignment', body: '{course}: {title} (due {date}).' },
    },
    material_new: {
      fr: { title: 'Nouveau support', body: '{course} : {title}' },
      en: { title: 'New material', body: '{course}: {title}' },
    },
    claim_reply: {
      fr: { title: 'Réclamation traitée', body: 'Votre réclamation ({course}) : {status}.' },
      en: { title: 'Claim processed', body: 'Your claim ({course}): {status}.' },
    },
    claim_new: {
      fr: { title: 'Nouvelle réclamation', body: '{student} conteste une note de {course}.' },
      en: { title: 'New grade claim', body: '{student} disputes a grade in {course}.' },
    },
    message_new: {
      fr: { title: 'Nouveau message', body: '{sender} : {text}' },
      en: { title: 'New message', body: '{sender}: {text}' },
    },
    application_update: {
      fr: { title: 'Dossier de pré-inscription', body: 'Statut : {status}.' },
      en: { title: 'Application update', body: 'Status: {status}.' },
    },
    reenroll_update: {
      fr: { title: 'Réinscription', body: 'Votre réinscription {year} : {status}.' },
      en: { title: 'Re-enrollment', body: 'Your {year} re-enrollment: {status}.' },
    },
    exam_convocation: {
      fr: { title: "Convocation d'examen", body: '{course} le {date} à {time}, salle {room}, place {seat}.' },
      en: { title: 'Exam notice', body: '{course} on {date} at {time}, room {room}, seat {seat}.' },
    },
    library_overdue: {
      fr: { title: 'Livre en retard', body: 'Merci de rapporter « {title} » (échéance {date}).' },
      en: { title: 'Overdue book', body: 'Please return "{title}" (due {date}).' },
    },
    absence_justification: {
      fr: { title: "Justificatif d'absence", body: 'Votre justificatif : {status}.' },
      en: { title: 'Absence justification', body: 'Your justification: {status}.' },
    },
    attendance_alert_staff: {
      fr: { title: 'Alerte assiduité', body: '{student} : {count} absences non justifiées en {course}.' },
      en: { title: 'Attendance alert', body: '{student}: {count} unjustified absences in {course}.' },
    },
  });

  mod_academic(d, C);
  mod_auth_extra(d, C);
  mod_learning(d, C);
  mod_grades(d, C);
  mod_attendance(d, C);
  mod_finance(d, C);
  mod_comms(d, C);
  mod_registration(d, C);
  mod_campus(d, C);
  mod_reports(d, C);
  mod_jobs(d, C);
}

// ---------- MODULES COMPLÉMENTAIRES (cahier des charges complet) ----------
mountModules({
  express, router, app, pool, crypto, bcrypt, axios, upload, authLimiter,
  requireAuth, requireRole, asyncHandler, audit, notifyUser, sendSms, sendEmail,
  generateOtp, storeOtp, verifyAndConsumeOtp, normalizePhone, normalizeEmail, hashToken,
  signAccessToken, createRefreshToken, serializeUser, NOTIF_I18N, currentAcademicYear,
  BCRYPT_COST, getIo: () => io,
});

// ---------- HEALTH ----------

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({
      status: 'ok',
      service: 'UniConnect API',
      database: 'connected',
      redis: redisClient ? 'configured' : 'memory',
      uptime: process.uptime(),
    });
  } catch (e) {
    res.status(503).json({ status: 'error', message: e.message });
  }
});

app.use('/api/v1', router);

app.use((err, req, res, next) => {
  console.error(`[Erreur] ${req.method} ${req.originalUrl} →`, err.message);
  const pg = { '23505': [409, 'Cette valeur existe déjà.'], '23503': [409, 'Élément lié à d’autres données.'],
    '22P02': [400, 'Identifiant ou format invalide.'], '23514': [400, 'Valeur non autorisée.'] }[err.code];
  const code = err.status || (pg && pg[0]) || 500;
  res.status(code).json({
    statusCode: code,
    message: err.status ? err.message : (pg ? pg[1] : code === 500 ? 'Erreur interne' : err.message),
    path: req.originalUrl,
  });
});

// ============================================================================
// SOCKET.IO (temps réel — présence, annonces)
// ============================================================================

const httpServer = http.createServer(app);
const io = new SocketIOServer(httpServer, {
  cors: { origin: '*' },
  path: '/realtime/socket.io',
});

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth && socket.handshake.auth.token;
    const payload = jwt.verify(token, JWT_SECRET);
    socket.user = { id: payload.sub, role: payload.role };
    next();
  } catch {
    next(new Error('unauthorized'));
  }
});

io.on('connection', (socket) => {
  socket.join(`user:${socket.user.id}`);
  socket.on('joinUser', () => socket.join(`user:${socket.user.id}`));
  socket.on('joinCourse', async (courseId) => {
    try {
      const ok = socket.user.role === 'etudiant'
        ? (await pool.query(`SELECT 1 FROM enrollments WHERE student_id=$1 AND course_id=$2 AND status='inscrit'`, [socket.user.id, courseId])).rowCount > 0
        : socket.user.role === 'enseignant'
          ? (await pool.query('SELECT 1 FROM courses WHERE id=$1 AND teacher_id=$2', [courseId, socket.user.id])).rowCount > 0
          : true;
      if (ok) socket.join(`course:${courseId}`);
    } catch (_) {}
  });
  socket.on('joinSession', (sessionId) => socket.join(`session:${sessionId}`));
});

// ============================================================================
// DÉMARRAGE
// ============================================================================

const SUPABASE = {
  url: (process.env.SUPABASE_URL || '').replace(/\/$/, ''),
  key: process.env.SUPABASE_SERVICE_ROLE_KEY || '',
  bucket: process.env.SUPABASE_BUCKET || 'uniconnect-files',
};
SUPABASE.enabled = !!(SUPABASE.url && SUPABASE.key);
/** En-têtes d'authentification : clé « service_role » (JWT) ou nouvelle clé secrète « sb_secret_… ». */
const sbHeaders = (extra = {}) => ({
  ...(SUPABASE.key.startsWith('sb_') ? {} : { Authorization: `Bearer ${SUPABASE.key}` }),
  apikey: SUPABASE.key,
  ...extra,
});

/** Crée le bucket privé Supabase s'il n'existe pas (sans effet s'il existe déjà). */
async function ensureStorageBucket() {
  if (!SUPABASE.enabled) {
    console.warn('[Stockage] Supabase non configuré : fichiers sur disque local (perdus à chaque redéploiement sur Render).');
    return;
  }
  try {
    await axios.post(`${SUPABASE.url}/storage/v1/bucket`,
      { id: SUPABASE.bucket, name: SUPABASE.bucket, public: false, file_size_limit: 10485760 },
      { headers: sbHeaders(), timeout: 15000 });
    console.log(`[Stockage] Bucket Supabase « ${SUPABASE.bucket} » créé.`);
  } catch (e) {
    const msg = e.response ? JSON.stringify(e.response.data) : e.message;
    if (e.response && (e.response.status === 409 || /already exists|Duplicate/i.test(msg))) console.log(`[Stockage] Bucket Supabase « ${SUPABASE.bucket} » prêt.`);
    else console.error('[Stockage] Impossible de vérifier le bucket Supabase :', msg);
  }
}

function validateConfig() {
  if (process.env.NODE_ENV === 'production' &&
      (!process.env.JWT_ACCESS_SECRET || process.env.JWT_ACCESS_SECRET.includes('changez_moi'))) {
    console.error('[Config] JWT_ACCESS_SECRET obligatoire en production.');
    process.exit(1);
  }
  if (!process.env.JWT_ACCESS_SECRET || process.env.JWT_ACCESS_SECRET.includes('changez_moi')) {
    console.warn('[Config] JWT_ACCESS_SECRET par défaut — changez-le en production.');
  }
  if (!process.env.DATABASE_URL && !process.env.DB_HOST) {
    console.warn('[Config] DATABASE_URL manquant.');
  }
}

validateConfig();

initDatabase()
  .then(() => {
    httpServer.listen(PORT, () => {
      console.log(`UniConnect API démarrée sur le port ${PORT}`);
      console.log(`  API      : http://localhost:${PORT}/api/v1`);
      console.log(`  Santé    : http://localhost:${PORT}/health`);
      console.log(`  Temps réel : ws://localhost:${PORT}/realtime/socket.io`);
      console.log(`  Auth étudiants : matricule + téléphone + OTP SMS`);
      console.log(`  Auth personnel  : email / téléphone + mot de passe`);
    });
  })
  .catch((err) => {
    console.error('[DB] Échec init :', err.message);
    process.exit(1);
  });

function shutdown(signal) {
  console.log(`\n[${signal}] Arrêt...`);
  httpServer.close(() => {
    pool.end().then(() => process.exit(0));
  });
  setTimeout(() => process.exit(1), 10000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
