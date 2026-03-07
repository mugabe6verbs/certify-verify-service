import express from 'express'
import axios from 'axios'
import admin from 'firebase-admin'
import cors from 'cors'
import dns from 'dns/promises'
import helmet from 'helmet'
import compression from 'compression'
import rateLimit from 'express-rate-limit'
import crypto from 'crypto'

const {
  PORT = 8080,
  FIREBASE_PROJECT_ID,
  FIREBASE_CLIENT_EMAIL,
  FIREBASE_PRIVATE_KEY,
  ALLOW_ORIGINS = 'http://localhost:5173,https://certificate-generator-345be.web.app,https://certificate-generator-345be.firebaseapp.com,https://certify-verify-service-2.onrender.com',
  PUBLIC_SITE_URL = 'https://certificate-generator-345be.web.app',
  ALLOW_MANUAL_PRO,
  
  PESA_CONSUMER_KEY,
  PESA_CONSUMER_SECRET,
  PESA_BASE = 'demo',  // 'demo' | 'live'
  PESA_IPN_ID,
  VERIFY_CNAME_TARGET = 'custom.getcertifyhq.com',
  ADMIN_PASSWORD 
} = process.env

const FREE_TEMPLATES = ['minimal', 'classic-border']

const PRO_TEMPLATES = [
  'modern',
  'luxury',
  'photo',
  'academic-seal',
  'creative'
]

const ALL_TEMPLATES = [...FREE_TEMPLATES, ...PRO_TEMPLATES]


/* ============== Small helpers ============== */
const clean = (s) => (s || '').trim().replace(/^"(.*)"$/, '$1').replace(/^'(.*)'$/, '$1')
const mask  = (s) => (s && s.length >= 8 ? s.slice(0,4)+'…'+s.slice(-4) : '(empty)')
function serverOrigin(req) {
  const xfProto = (req.headers['x-forwarded-proto'] || '').toString().split(',')[0] || 'https'
  const host = req.headers.host
  return `${xfProto}://${host}`
}
function normalizeCountryCode(input) {
  if (!input) return null
  const cc = String(input).trim().toUpperCase()
  return /^[A-Z]{2}$/.test(cc) ? cc : null
}
function generateSerial() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
  const bytes = crypto.randomBytes(12)

  let serial = ''

  for (let i = 0; i < 12; i++) {
    serial += chars[bytes[i] % chars.length]

    if (i === 3 || i === 7) {
      serial += '-'
    }
  }

  return serial
}

function normalizeDomain(input) {
  if (!input) return null

  let d = String(input).trim().toLowerCase()

  d = d.replace(/^https?:\/\//, '')
  d = d.replace(/\/+$/, '')

  return d
}

function validateDataUrlSize(dataUrl, maxBytes = 300000) {
  if (!dataUrl) return true
  if (typeof dataUrl !== 'string') return false

  const parts = dataUrl.split(',')
  if (parts.length !== 2) return false

  const base64 = parts[1]
  const size = Buffer.byteLength(base64, 'base64')

  return size <= maxBytes
}

/* ============== Firebase Admin ============== */
const privateKey = clean(FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n')
const hasFirebaseCreds = !!(FIREBASE_PROJECT_ID && FIREBASE_CLIENT_EMAIL && privateKey)
let db = null
try {
  if (hasFirebaseCreds) {
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: FIREBASE_PROJECT_ID,
        clientEmail: FIREBASE_CLIENT_EMAIL,
        privateKey
      })
    })
    db = admin.firestore()
    console.log('Firebase Admin initialized')
  } else {
    console.warn('⚠ Firebase credentials not set — Firestore writes disabled.')
  }
} catch (e) {
  console.warn('⚠ Firebase Admin init warning:', e?.message || e)
}
const ALLOW_MANUAL_PRO_ENV = String(ALLOW_MANUAL_PRO || '').toLowerCase() === 'true'

/* ============== Pricing (USD) ============== */
const CURRENCY = process.env.PESA_CURRENCY || 'KES'
const AMOUNT_BY_PLAN = { pro_monthly: 29, pro_yearly: 290 }
const INTERVAL_BY_PLAN = { pro_monthly: 'month', pro_yearly: 'year' }

function amountToPlanId(amount) {
  const a = Number(amount)

  if (Math.abs(a - 29) < 0.01) {
    return "pro_monthly"
  }

  if (Math.abs(a - 290) < 0.01) {
    return "pro_yearly"
  }

  return null
}

function addInterval(ms, interval) {
  const d = new Date(ms)
  if (interval === 'year') d.setUTCFullYear(d.getUTCFullYear() + 1)
  else d.setUTCMonth(d.getUTCMonth() + 1)
  return d.getTime()

  
}
// ================= QUOTA HELPERS  =================

// YYYY-MM-DD (UTC)
function todayKey() {
  return new Date().toISOString().slice(0, 10)
}

// YYYY-MM (UTC)
function monthKey() {
  return new Date().toISOString().slice(0, 7)
}

// Monthly count from users.daily map
function computeMonthlyCount(data) {
  const daily = data?.daily || {}
  const prefix = monthKey()
  let sum = 0

  for (const [k, v] of Object.entries(daily)) {
    if (typeof k === "string" && k.startsWith(prefix)) {
      const n = Number(v || 0)
      if (Number.isFinite(n) && n > 0) sum += n
    }
  }
  return sum
}

// Daily + Monthly limits by plan (SERVER AUTHORITY)
const PLAN_LIMITS = {
  free:        { monthly: 10,  daily: 5   },
  pro_monthly:{ monthly: 300, daily: 100 },
  pro_yearly: { monthly: 1000,daily: 300 },
  pro_admin: { monthly: 100000, daily: 10000 },
  pro:        { monthly: 300, daily: 100 } // fallback
}

// Resolve plan → limits safely
function resolveLimits(data) {
  // ADMIN override
  if (data?.isAdmin === true) {
    return PLAN_LIMITS.pro_admin
  }

  const raw = String(data?.planId || "free").toLowerCase()

  return (
    PLAN_LIMITS[raw] ||
    (raw.includes("year")
      ? PLAN_LIMITS.pro_yearly
      : raw.includes("month")
      ? PLAN_LIMITS.pro_monthly
      : PLAN_LIMITS.free)
  )
}

// -----------------------------
// Atomic check + consume quota
// (non-transaction version)
// -----------------------------
async function checkAndConsumeQuota(uid, count = 1) {
  if (!db) throw new Error("DB not available")

  const userRef = db.collection("users").doc(uid)

  return await db.runTransaction(async (tx) => {
    return await checkAndConsumeQuotaTx(tx, uid, count)
  })
}

// Alias (kept for API compatibility)
async function checkAndReserveQuota(uid, count) {
  return checkAndConsumeQuota(uid, count)
}

// -----------------------------
// Transaction-safe quota checker
// -----------------------------
async function checkAndConsumeQuotaTx(tx, uid, count = 1) {
  if (!db) throw new Error("DB not available")

  const userRef = db.collection("users").doc(uid)
  const snap = await tx.get(userRef)
  const data = snap.exists ? snap.data() : {}

  const limits = resolveLimits(data)

  const day = todayKey()
  const dailyMap = data.daily || {}

  const usedToday = Number(dailyMap[day] || 0)
  const usedThisMonth = computeMonthlyCount({ daily: dailyMap })

  // Enforce limits BEFORE consuming
  if (usedToday + count > limits.daily) {
    return { ok: false, reason: "daily", limit: limits.daily }
  }

  if (usedThisMonth + count > limits.monthly) {
    return { ok: false, reason: "monthly", limit: limits.monthly }
  }

  //  Atomic, nested, race-safe increment
  tx.set(
    userRef,
    {
      daily: {
        [day]: admin.firestore.FieldValue.increment(count),
      },
      lastIssuedAt: admin.firestore.FieldValue.serverTimestamp(),
    },
    { merge: true }
  )

  return {
    ok: true,
    plan: String(data?.planId || "free").toLowerCase(),
    usedToday: usedToday + count,
    usedThisMonth: usedThisMonth + count,
  }
}


/* ============== Billing Reconcile Helper ============== */
 async function reconcileForUser(uid) {
  if (!db) throw new Error("DB not available")

  // Find latest paid subscription order
  const snap = await db
  .collection("orders")
  .where("uid", "==", uid)
  .where("status", "==", "paid")
  .where("reconciled", "==", false)
  .orderBy("paidAt", "desc")
  .limit(1)
  .get()

  if (snap.empty) {
    return { ok: true, reconciled: false, reason: "no_paid_orders" }
  }

  const orderDoc = snap.docs[0]
  const order = orderDoc.data()

  const finalPlanId =
    order.planId || amountToPlanId(order.amount) || "pro_monthly"

  const interval = INTERVAL_BY_PLAN[finalPlanId] || "month"
  const userRef = db.collection("users").doc(uid)
  const userSnap = await userRef.get()
  const now = Date.now()
  const existingProUntil = Number(userSnap.get("proUntil") || 0)

 if (existingProUntil > now) {
  return {
    ok: true,
    reconciled: false,
    reason: "subscription_already_active",
  }
 }
 if (!userSnap.exists) {
  return { ok: false, reconciled: false, reason: "user_missing" }
 }

 const base = Math.max(
  Date.now(),
  Number(userSnap.get("proUntil") || 0)
 )

 const proUntil = addInterval(base, interval)


  // Idempotent upgrade (safe to run multiple times)
  await userRef.set(
    {
      pro: true,
      planId: finalPlanId,
      proUntil,
      proSetAt: admin.firestore.FieldValue.serverTimestamp(),
      lastPayment: {
        provider: order.provider || "pesapal",
        orderId: orderDoc.id,
        reconciledAt: admin.firestore.FieldValue.serverTimestamp(),
      },
    },
    { merge: true }
  )
 await orderDoc.ref.update({
  reconciled: true,
  reconciledAt: admin.firestore.FieldValue.serverTimestamp(),
 })
  return {
    ok: true,
    reconciled: true,
    planId: finalPlanId,
    orderId: orderDoc.id,
  }
 }


 /* ============== Pesapal config ============== */
 const PESA_KEY    = clean(PESA_CONSUMER_KEY)
 const PESA_SECRET = clean(PESA_CONSUMER_SECRET)
 const PESA_MODE   = (PESA_BASE || 'auto').toLowerCase()
 const PESA_URLS   = {
  demo: 'https://cybqa.pesapal.com/pesapalv3',
  live: 'https://pay.pesapal.com/v3'
 }
  function isInvalidKeyErr(e) {
  const code = e?.response?.data?.error?.code || ''
  return String(code).toLowerCase().includes('invalid_consumer_key_or_secret_provided')
 }
 async function tokenFor(base) {
  const url = PESA_URLS[base]
  const { data } = await axios.post(
    `${url}/api/Auth/RequestToken`,
    { consumer_key: PESA_KEY, consumer_secret: PESA_SECRET },
    { headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, timeout: 15000 }
  )
  if (!data?.token) throw new Error(`No token in Pesapal token response: ${JSON.stringify(data)}`)
  return { token: data.token, base, url }
 }
 async function pesaToken(preferred = PESA_MODE) {
  if (!PESA_KEY || !PESA_SECRET) throw new Error('Missing PESA_CONSUMER_KEY/SECRET')
  const order = (preferred === 'auto') ? ['demo','live'] : [preferred, preferred === 'demo' ? 'live' : 'demo']
  let lastErr = null
  for (const b of order) {
    try { return await tokenFor(b) }
    catch (e) {
      lastErr = e
      if (isInvalidKeyErr(e)) continue
      throw e
    }
  }
  throw lastErr
 }

  /* ============== App / CORS / Middleware ============== */
 const app = express()
 app.use((req, res, next) => {
  res.setTimeout(15000, () => {
    res.status(503).json({ ok: false, error: 'Request timeout' })
  })
  next()
 })
 app.set('trust proxy', 1)

 const allowList = (ALLOW_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean)

 const corsOptions = {
  origin(origin, cb) {
    
    if (!origin) return cb(null, true) // server-to-server, redirects
    if (allowList.includes(origin)) return cb(null, true)

    
    return cb(null, false)
  },
  methods: ['GET', 'POST', 'OPTIONS', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    
  ],
  credentials: true,
  optionsSuccessStatus: 204,
 }

 app.use(cors(corsOptions))
 app.options('*', cors(corsOptions))

 app.use(helmet())
 app.disable('x-powered-by')

 app.use(compression())
 app.use(express.json({ limit: '2mb', strict: true}))

 /* ============== Rate limiters ============== */
 const globalLimiter = rateLimit({ windowMs: 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false })
 const pesapalLimiter = rateLimit({ windowMs: 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false })
 const ipnLimiter = rateLimit({ windowMs: 60 * 1000, max: 300, standardHeaders: true, legacyHeaders: false })

 app.use(globalLimiter)

 const adminVerifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,                  // 5 attempts per window
  standardHeaders: true,
  legacyHeaders: false
 })

  const bulkLimiter = rateLimit({
  windowMs: 60 * 1000,   // 1 minute
  max: 5,               // max 5 bulk batches per minute per user/IP
  standardHeaders: true,
  legacyHeaders: false
 })

 const verifyLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false
 })

 /* ======================================================
   AUTH
 ====================================================== */
 async function verifyToken(req) {
  try {
    const header = req.headers.authorization || ""

    if (!header.startsWith("Bearer ")) return null

    const token = header.slice(7).trim()
    if (!token) return null

    return await admin.auth().verifyIdToken(token, true)
  } catch {
    return null
  }
 }
 async function authenticate(req, res, next) {
  const decoded = await verifyToken(req)
  if (!decoded) {
    return res.status(401).json({ ok: false, error: "Invalid or missing token" })
  }
  if (decoded.disabled === true) {
    return res.status(403).json({ ok: false, error: "User disabled" })
  }
  req.user = decoded
  next()
 }


 /* ============== Health & Debug (protected) ============== */
  app.get(['/health','/api/health'], (_req, res) => {
  res.json({ ok: true })
 })

 app.get('/pesapal/health', authenticate, async (req, res) => {
  try {
    const probe = String(req.query.probe || '') === '1'
    let baseResolved = null
    if (probe) {
      const { base } = await pesaToken()
      baseResolved = base
    }
    res.json({ ok: true, configuredBase: PESA_MODE, baseResolved, keysPresent: !!(PESA_KEY && PESA_SECRET) })
  } catch (e) {
    res.status(500).json({ ok:false, error: e?.response?.data || e?.message || String(e) })
  }
 })



 /* ============== Home page (info) - SECURED FOR PUBLIC ACCESS ============== */
 const IS_PROD = process.env.NODE_ENV === 'production'
 app.get('/', async (req, res) => {
  let decoded = null

  try {
    decoded = await verifyToken(req)
  } catch {
    decoded = null
  }

  if (IS_PROD || !decoded || decoded.admin !== true) {
    return res.json({ ok: true, service: 'Certify Verify Service', status: 'running' })
  }

  // Otherwise (admin + dev), display the full debug info
  const maskedSA = (FIREBASE_CLIENT_EMAIL || '').replace(/(.{3}).+(@.+)/, '$1***$2')
  const origin = serverOrigin(req)
  res.type('html').send(`
    <html><body style="font-family:system-ui;padding:16px">
      <h2>Certify Verify Service</h2>
      <ul>
        <li>Project: <code>${FIREBASE_PROJECT_ID || '—'}</code></li>
        <li>Firebase creds set: <strong style="color:${hasFirebaseCreds?'green':'crimson'}">${hasFirebaseCreds}</strong></li>
        <li>Allowed origins: ${allowList.map(o=>`<code>${o}</code>`).join(', ') || '—'}</li>
        <li>Pesapal configuredBase: <code>${PESA_MODE}</code></li>
      </ul>
      <p>(sensitive info hidden)</p>

      <p>Health: <a href="/health">/health</a></p>
      <p>Pesapal health: <a href="/pesapal/health?probe=1">/pesapal/health?probe=1</a></p>
      <p><strong>Register IPN (admin only):</strong> <code>GET ${origin}/pesapal/registerIPN</code></p>
    </body></html>
  `)
 })


 /* ============== Manual Pro (dev/test) ============== */
 async function isManualProEnabled() {
  if (ALLOW_MANUAL_PRO_ENV) return true
  if (!db) return false
  try {
    const snap = await db.collection('config').doc('flags').get()
    return !!(snap.exists && snap.get('allowManualPro') === true)
  } catch { return false }
 }
  app.post(['/manualPro','/api/manualPro','/admin/manualPro'], async (req, res) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(404).json({ ok: false })
  }
  try {
    if (!db) return res.status(500).json({ ok:false, error:'Server missing Firebase credentials' })
    const { idToken } = req.body || {}
 if (typeof idToken !== "string") {
  return res.status(400).json({ ok:false, error:"Invalid token" })
 }
    if (!idToken) return res.status(400).json({ ok:false, error:'Missing idToken' })
    const decoded = await admin.auth().verifyIdToken(String(idToken), true)
    const uid = decoded.uid
    if (!(await isManualProEnabled())) return res.status(403).json({ ok:false, error:'Manual Pro disabled' })
    await db.collection('users').doc(uid).set({
      pro: true,
      planId: 'pro_monthly',
      proUntil: addInterval(Date.now(), 'month'),
      proSetAt: admin.firestore.FieldValue.serverTimestamp(),
      lastPayment: { provider: 'manual' }
    }, { merge: true })
    res.json({ ok:true, uid })
  } catch (e) {
    res.status(500).json({ ok:false, error: e?.response?.data || e?.message || String(e) })
  }
 })

 /* ============== CERTIFICATES ISSUE  ============== */


 app.post('/api/certificates/issue', authenticate, async (req, res) => {
  try {
    if (!db) {
      return res.status(500).json({ ok: false, error: 'Server missing Firebase credentials' })
    }

    const uid = req.user?.uid
    if (!uid) {
      return res.status(401).json({ ok: false, error: 'Unauthorized' })
    }
 const data = req.body || {}
 // Validate image payload sizes
 if (
  !validateDataUrlSize(data.logoDataUrl) ||
  !validateDataUrlSize(data.sigDataUrl) ||
  !validateDataUrlSize(data.sigDataUrl2) ||
  !validateDataUrlSize(data.photoDataUrl) ||
  !validateDataUrlSize(data.sealDataUrl)
 ) {
  return res.status(400).json({
    ok: false,
    error: 'One or more images exceed allowed size limit'
  })
 }

 // Stronger payload guard (prevents empty or whitespace values)
 


    const userRef = db.collection('users').doc(uid)

    const result = await db.runTransaction(async (tx) => {
      /* ---------- READ PHASE ---------- */
      const userSnap = await tx.get(userRef)
      const userData = userSnap.data() || {}
      
      if (!userSnap.exists) {
  throw new Error('PRO_REQUIRED')
  }
      const orgId = userData.orgId || uid

      const orgRef = db.collection('orgs').doc(orgId)
      const orgSnap = await tx.get(orgRef)

   if (!orgSnap.exists) {
  throw new Error('ORG_NOT_FOUND')
   }

     const orgData = orgSnap.data() || {}
  if (
  !String(data.recipientName || '').trim() ||
  !String(data.courseTitle || '').trim() ||
  !String(orgData.name || '').trim()
) {
  throw new Error('MISSING_REQUIRED_FIELDS')
}
    
      // Pro check
  const rawProUntil = userData.proUntil

 let proUntil = null

 if (typeof rawProUntil === "number") {
  proUntil = rawProUntil
 } else if (rawProUntil?.toMillis) {
  proUntil = rawProUntil.toMillis()
 }

 if (!proUntil || Date.now() >= proUntil) {
  throw new Error("PRO_REQUIRED")
 }
  let serial = null
let lookupRef = null

for (let i = 0; i < 5; i++) {
  const trySerial = generateSerial()

  const ref = db.collection('certificateLookup').doc(trySerial)
  const snap = await tx.get(ref)

  if (!snap.exists) {
    serial = trySerial
    lookupRef = ref
    break
  }
}

if (!serial) {
  throw new Error('SERIAL_GENERATION_FAILED')
}
   // Determine verification domain at issuance time (LOCKED)
let domainUsed = normalizeDomain(new URL(PUBLIC_SITE_URL).hostname)

if (
  orgData?.customVerifyDomain &&
  orgData?.domainVerified === true
) {
  domainUsed = clean(orgData.customVerifyDomain)
}

 // Build verification URL (LOCKED FOREVER)
 const verifyUrl = `https://${domainUsed}/verify/${serial}`

      /* ---------- WRITE PHASE ---------- */
      const quotaResult = await checkAndConsumeQuotaTx(tx, uid, 1)
      if (!quotaResult.ok) {
        throw new Error(
          quotaResult.reason === "daily"
            ? `DAILY_LIMIT_${quotaResult.limit}`
            : `MONTHLY_LIMIT_${quotaResult.limit}`
        )
      }

      const now = admin.firestore.FieldValue.serverTimestamp()
      
      const certRef = db.collection('certificates').doc(serial)

      const orgCertRef = db.collection('orgs').doc(orgId).collection('certificates').doc(serial)

 
      const historyRef = certRef.collection('history').doc()
 
    /* ---------- TEMPLATE VALIDATION ---------- */
 let template = 'minimal' // safe default

 if (typeof data.template === 'string' && ALL_TEMPLATES.includes(data.template)) {
  template = data.template
 }

// Prevent Pro template usage by free users
if (PRO_TEMPLATES.includes(template)) {
  const isPro = proUntil && Date.now() < proUntil
  if (!isPro) {
    throw new Error('PRO_TEMPLATE_NOT_ALLOWED')
  }
 }

      const payload = {
  recipientName: String(data.recipientName || '').trim(),
  courseTitle: String(data.courseTitle || '').trim(),
  achievementText: data.achievementText || null,
  externalId: data.externalId || null,
  expiryDate: data.expiryDate || null,
  customNote: data.customNote || null,
  issueDate: data.issueDate || null,
  issuerName: data.issuerName || null,
  issuerPosition: data.issuerPosition || null,
  issuerName2: data.issuerName2 || null,
  issuerPosition2: data.issuerPosition2 || null,
  orgId, orgName: String(orgData.name || '').trim(),

  logoDataUrl: data.logoDataUrl || null,
  sigDataUrl: data.sigDataUrl || null,
  sigDataUrl2: data.sigDataUrl2 || null,
  
   photoDataUrl: data.photoDataUrl || null,
  sealDataUrl: data.sealDataUrl || null,

  template,
  accentColor: data.accentColor || '#CFAE49',
  titleText: data.titleText || 'Certificate',

  brand: data.brand || {},
  i18n: data.i18n || {},

  ownerUid: uid,
  serial,
  verificationDomain: domainUsed,
  verifyUrl,
  status: 'valid',
  visibility: 'public',
  immutable: true,
  createdAt: now,
  reserved: false
 }


      // Writes
      // Main certificate (legacy global collection)
 tx.set(certRef, payload, { merge: true })
 // Org-scoped certificate (fast org queries - lightweight)
tx.set(orgCertRef, {
  serial,
  recipientName: payload.recipientName,
  courseTitle: payload.courseTitle,
  orgName: payload.orgName,
  status: payload.status,
  template: payload.template,
  issueDate: payload.issueDate,
  expiryDate: payload.expiryDate || null,
  externalId: payload.externalId || null,
  titleText: payload.titleText || null,
  createdAt: payload.createdAt,
  ownerUid: payload.ownerUid,
  orgId: payload.orgId
}, { merge: true })

  // Global serial registry (verification snapshot)
tx.set(lookupRef, {
  serial,
  orgId,
  ownerUid: uid,

  orgName: payload.orgName,
  recipientName: payload.recipientName,
  courseTitle: payload.courseTitle,

  issueDate: payload.issueDate || null,
  expiryDate: payload.expiryDate || null,

  template: payload.template || "classic",
  brand: payload.brand || null,

  status: payload.status || "valid",
  visibility: payload.visibility || "public",

  verificationDomain: domainUsed,

  createdAt: now
}, { merge: true })
 // Issuance history
 tx.set(historyRef, {
  action: 'issued',
  by: uid,
  at: now,
  source: 'api',
  ip: req.ip
 })
    
   return { serial, verifyUrl }
    })

   
    
 // Safe post-transaction log
 console.log("ISSUED CERT:", { uid, serial: result.serial })

    return res.json({
  ok: true,
  serial: result.serial,
  verifyUrl: result.verifyUrl
})

  } catch (e) {
    console.error('ISSUE CERT ERROR', e)

    if (e.message === 'PRO_REQUIRED') {
      return res.status(403).json({ ok: false, error: 'Pro plan required' })
    }
      
if (e.message === 'MISSING_REQUIRED_FIELDS') {
  return res.status(400).json({
    ok: false,
    error: 'Missing required certificate fields'
  })
}
    if (e.message?.toLowerCase().includes('limit')) {
      return res.status(429).json({ ok: false, error: e.message })
    }

    if (e.message === 'SERIAL_GENERATION_FAILED') {
      return res.status(500).json({ ok: false, error: 'Failed to generate unique serial' })
    }

    return res.status(500).json({ ok: false, error: 'Server error' })
  }
})

/* ============== BULK CERTIFICATE PREPARE  ============== */

app.post(
  '/api/certificates/bulk/prepare',
  authenticate,
  bulkLimiter,
  async (req, res) => {
    try {
      if (!db) {
        return res.status(500).json({ ok: false, error: 'Server missing Firebase credentials' })
      }

      const uid = req.user?.uid
      if (!uid) {
        return res.status(401).json({ ok: false, error: 'Unauthorized' })
      }

      const { count, meta = {} } = req.body || {}

      if (!Number.isInteger(count) || count <= 0 || count > 500) {
        return res.status(400).json({
          ok: false,
          error: 'Invalid count (1–500 allowed per batch)'
        })
      }

      const userRef = db.collection('users').doc(uid)
      const batchRef = db.collection('bulkBatches').doc()

      const result = await db.runTransaction(async (tx) => {
        /* ---------- READ PHASE ---------- */
       const userSnap = await tx.get(userRef)

       if (!userSnap.exists) {
      throw new Error('PRO_REQUIRED')
   }

      const userData = userSnap.data() || {}

      const rawProUntil = userData.proUntil

      let proUntil = null

      if (typeof rawProUntil === "number") {
     proUntil = rawProUntil
    } else if (rawProUntil?.toMillis) {
      proUntil = rawProUntil.toMillis()
   }

   if (!proUntil || Date.now() >= proUntil) {
  throw new Error("PRO_REQUIRED")
   }

  const orgId = userData.orgId || uid
        // Generate all serials (READ ONLY)
        const serials = []
const serialSet = new Set()

let attempts = 0
const MAX_ATTEMPTS = count * 10

while (serials.length < count && attempts < MAX_ATTEMPTS) {
  attempts++

  const s = generateSerial()

  const lookupRef = db.collection('certificateLookup').doc(s)
  const snap = await tx.get(lookupRef)

  if (!snap.exists && !serialSet.has(s)) {
    serials.push(s)
    serialSet.add(s)
  }
}

if (serials.length < count) {
  throw new Error('SERIAL_GENERATION_FAILED')
}


        /* ---------- WRITE PHASE ---------- */
        const quotaResult = await checkAndConsumeQuotaTx(tx, uid, count)
        if (!quotaResult.ok) {
          throw new Error(
            quotaResult.reason === 'daily'
              ? `Daily bulk limit reached (${quotaResult.limit}/day)`
              : `Monthly bulk limit reached (${quotaResult.limit}/month)`
          )
        }

        const now = admin.firestore.FieldValue.serverTimestamp()
        tx.set(batchRef, { ownerUid: uid, orgId, count, createdAt: now, meta})
        // Lock serials
        for (const s of serials) {

  const certRef = db.collection('certificates').doc(s)

  const orgCertRef = db
    .collection('orgs')
    .doc(orgId)
    .collection('certificates')
    .doc(s)

  const lookupRef = db.collection('certificateLookup').doc(s)

  // reserve certificate
  tx.set(certRef, {
  reserved: true,
  reservedBy: uid,
  batchId: batchRef.id,
  reservedAt: now,
  reservationExpiresAt: admin.firestore.Timestamp.fromMillis(
    Date.now() + 30 * 60 * 1000
  )
})

  // reserve org certificate
   tx.set(orgCertRef, {
  reserved: true,
  reservedBy: uid,
  batchId: batchRef.id,
  reservedAt: now,
  reservationExpiresAt: admin.firestore.Timestamp.fromMillis(
    Date.now() + 30 * 60 * 1000
  ),
  ownerUid: uid,
  orgId
})

  // reserve lookup
  tx.set(lookupRef, {
    serial: s,
    orgId,
    ownerUid: uid,
    reserved: true,
    batchId: batchRef.id,
    createdAt: now
  })
}
        return { serials, batchId: batchRef.id }
      })

      return res.json({ ok: true, ...result })

    } catch (e) {
      console.error('BULK PREPARE ERROR', e)

      if (e.message === 'PRO_REQUIRED') {
        return res.status(403).json({ ok: false, error: 'Pro plan required' })
      }
    if (e.message === 'SERIAL_GENERATION_FAILED') {
    return res.status(500).json({
      ok: false,
      error: 'Failed to generate unique serials. Please retry.'
    })
  }
      if (e.message?.toLowerCase().includes('limit')) {
        return res.status(429).json({ ok: false, error: e.message })
      }

      return res.status(500).json({ ok: false, error: 'Server error' })
    }
  }
)

/* ============== CERTIFICATE REVOKE ============== */
app.post('/api/certificates/revoke', authenticate, async (req, res) => {
  try {
    if (!db) {
      return res.status(500).json({ ok: false, error: 'Server missing Firebase credentials' })
    }

    const uid = req.user?.uid
    const { serial, reason } = req.body || {}

    const SERIAL_RE = /^([A-Z0-9]{6,16}|[A-Z0-9]{4}(-[A-Z0-9]{4}){2})$/

    const normalizedSerial = String(serial || '').toUpperCase()

    if (!SERIAL_RE.test(normalizedSerial)) {
    return res.status(400).json({ ok: false, error: 'Invalid serial format' })
   }
  const lookupRef = db.collection('certificateLookup').doc(normalizedSerial)

await db.runTransaction(async (tx) => {

  const lookupSnap = await tx.get(lookupRef)

  if (!lookupSnap.exists) {
    throw new Error('NOT_FOUND')
  }

  const { orgId } = lookupSnap.data()

  const certRef = db.collection('certificates').doc(normalizedSerial)

  const orgCertRef = db
    .collection('orgs')
    .doc(orgId)
    .collection('certificates')
    .doc(normalizedSerial)

  const snap = await tx.get(certRef)

  if (!snap.exists) {
    throw new Error('NOT_FOUND')
  }

  const cert = snap.data()

  if (cert.reserved === true) {
    throw new Error('NOT_FOUND')
  }

  if (cert.ownerUid !== uid) {
    throw new Error('FORBIDDEN')
  }

  if (cert.status === 'revoked') {
    throw new Error('ALREADY_REVOKED')
  }

  const now = admin.firestore.FieldValue.serverTimestamp()

  const updatePayload = {
    status: 'revoked',
    revokeReason: reason || 'Revoked by issuer',
    revokedAt: now,
    revokedBy: uid
  }

  // Update legacy certificate
  tx.update(certRef, updatePayload)

  // Update org certificate
  tx.update(orgCertRef, updatePayload)

  // Write history
  tx.set(certRef.collection('history').doc(), {
    action: 'revoked',
    by: uid,
    reason: reason || 'Revoked by issuer',
    at: now,
    source: 'api',
    ip: req.ip
  })
})

    return res.json({ ok: true })

  } catch (e) {
    if (e.message === 'NOT_FOUND') {
      return res.status(404).json({ ok: false, error: 'Certificate not found' })
    }
    if (e.message === 'FORBIDDEN') {
      return res.status(403).json({ ok: false, error: 'Not allowed' })
    }
    if (e.message === 'ALREADY_REVOKED') {
      return res.status(400).json({ ok: false, error: 'Already revoked' })
    }

    console.error('REVOKE ERROR', e)
    return res.status(500).json({ ok: false, error: 'Server error' })
  }
})

/* ============== CERTIFICATE RESTORE ============== */
app.post('/api/certificates/restore', authenticate, async (req, res) => {
  try {
    if (!db) {
      return res.status(500).json({ ok: false, error: 'Server missing Firebase credentials' })
    }

    const uid = req.user?.uid
    const { serial } = req.body || {}

    const SERIAL_RE = /^([A-Z0-9]{6,16}|[A-Z0-9]{4}(-[A-Z0-9]{4}){2})$/

    const normalizedSerial = String(serial || '').toUpperCase()

   if (!SERIAL_RE.test(normalizedSerial)) {
  return res.status(400).json({ ok: false, error: 'Invalid serial format' })
   }
  const lookupRef = db.collection('certificateLookup').doc(normalizedSerial)

await db.runTransaction(async (tx) => {

  const lookupSnap = await tx.get(lookupRef)

  if (!lookupSnap.exists) {
    throw new Error('NOT_FOUND')
  }

  const { orgId } = lookupSnap.data()

  const certRef = db.collection('certificates').doc(normalizedSerial)

  const orgCertRef = db
    .collection('orgs')
    .doc(orgId)
    .collection('certificates')
    .doc(normalizedSerial)

  const snap = await tx.get(certRef)

  if (!snap.exists) {
    throw new Error('NOT_FOUND')
  }

  const cert = snap.data()

  if (cert.ownerUid !== uid) {
    throw new Error('FORBIDDEN')
  }

  if (cert.status !== 'revoked') {
    throw new Error('NOT_REVOKED')
  }

  const now = admin.firestore.FieldValue.serverTimestamp()

  const updatePayload = {
    status: 'valid',
    revokeReason: null,
    revokedAt: null,
    revokedBy: null,
    restoredAt: now,
    restoredBy: uid
  }

  // update legacy certificate
  tx.update(certRef, updatePayload)

  // update org certificate
  tx.update(orgCertRef, updatePayload)

  // history log
  tx.set(certRef.collection('history').doc(), {
    action: 'restored',
    by: uid,
    at: now,
    source: 'api',
    ip: req.ip
  })
 })

    return res.json({ ok: true })

  } catch (e) {
    if (e.message === 'NOT_FOUND') {
      return res.status(404).json({ ok: false, error: 'Certificate not found' })
    }
    if (e.message === 'FORBIDDEN') {
      return res.status(403).json({ ok: false, error: 'Not allowed' })
    }
    if (e.message === 'NOT_REVOKED') {
      return res.status(400).json({ ok: false, error: 'Certificate is not revoked' })
    }

    console.error('RESTORE ERROR', e)
    return res.status(500).json({ ok: false, error: 'Server error' })
  }
})

/* ============== VERIFICATION ============== */

app.get('/verify/:serial', verifyLimiter, async (req, res) => {
  try {
    if (!db) {
      return res.status(500).json({ ok: false })
    }

    const rawSerial = String(req.params.serial || '').toUpperCase()

    const SERIAL_RE = /^([A-Z0-9]{6,16}|[A-Z0-9]{4}(-[A-Z0-9]{4}){2})$/

    if (!SERIAL_RE.test(rawSerial)) {
      return res.status(400).json({ ok: false, error: 'Invalid format' })
    }

    let cert = null

const lookupSnap = await db.collection('certificateLookup').doc(rawSerial).get()
 if (lookupSnap.exists) {
  const { orgId } = lookupSnap.data()

  const orgCertSnap = await db
    .collection('orgs')
    .doc(orgId)
    .collection('certificates')
    .doc(rawSerial)
    .get()

  if (orgCertSnap.exists) {
    cert = orgCertSnap.data()
  }
}

if (!cert) {
  const legacySnap = await db.collection('certificates').doc(rawSerial).get()

  if (!legacySnap.exists) {
    return res.status(404).json({ ok: false })
  }

  cert = legacySnap.data()
}

    // Block archived
    if (cert.status === 'archived') {
      return res.status(404).json({ ok: false })
    }
    
    // Block private certificates from public verification
if (cert.visibility === 'private') {
  return res.status(404).json({ ok: false })
}
    // Fetch org for domain enforcement
    let orgData = null
    if (cert.orgId) {
      const orgSnap = await db.collection('orgs').doc(cert.orgId).get()
      if (orgSnap.exists) {
        orgData = orgSnap.data()
      }
    }

    //  Domain binding enforcement
    if (
      orgData?.customVerifyDomain &&
      orgData?.domainVerified === true
    ) {
      const requestHost = req.hostname.toLowerCase()
      const expectedHost = orgData.customVerifyDomain.toLowerCase()

      if (requestHost !== expectedHost) {
        return res.status(403).json({ ok: false })
      }
    }

    //  Log verification server-side
   setImmediate(() => {
  db.collection('verificationLogs')
    .add({
      serial: rawSerial,
      orgId: cert.orgId || null,
      viewedAt: admin.firestore.FieldValue.serverTimestamp(),
      ip: req.ip,
      ua: req.headers['user-agent'] || null
    })
    .catch(() => {})
})
      
    // Detect expiry
   let finalStatus = cert.status

if (
  cert.status === "valid" &&
  cert.expiryDate
) {
  const expiry = new Date(cert.expiryDate).getTime()

  if (!isNaN(expiry) && Date.now() > expiry) {
    finalStatus = "expired"
  }
}
    //  Return only public-safe fields
    const publicPayload = {
      serial: cert.serial,
      recipientName: cert.recipientName,
      courseTitle: cert.courseTitle,
      orgName: cert.orgName,
      issueDate: cert.issueDate,
      expiryDate: cert.expiryDate || null,
      status: finalStatus,
      revokeReason: cert.revokeReason || null,
      revokedAt: cert.revokedAt || null,
      createdAt: cert.createdAt || null,
      template: cert.template,
      brand: cert.brand || null,
   }
     res.set("Cache-Control", "public, max-age=0, s-maxage=300");
    return res.json({ ok: true, certificate: publicPayload })

  } catch (e) {
    console.error('VERIFY ERROR', e)
    return res.status(500).json({ ok: false })
  }
})

/* ============== Admin rescue ============== */

async function logAdminAction({ action, adminUid, targetUid, meta = {} }) {
  if (!db) return

  try {
    await db.collection("adminLogs").add({
      action,
      adminUid,
      targetUid: targetUid || null,
      meta,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    })
  } catch (e) {
    console.warn("⚠ Failed to write admin log:", e?.message || e)
  }
}


async function requireAdminAuth(req, res) {
  try {
    const authHeader = (req.headers.authorization || "").toString()

    if (!authHeader.startsWith("Bearer ")) {
      res.status(401).json({ ok: false, error: "Missing Bearer token" })
      return null
    }

    
    const decoded = await verifyToken(req)


    if (decoded.admin !== true) {
      res.status(403).json({ ok: false, error: "Admin access required" })
      return null
    }

    return decoded // uid, email, claims
  } catch (err) {
    console.error("requireAdminAuth error:", err?.message || err)
    res.status(401).json({ ok: false, error: "Invalid or expired token" })
    return null
  }
  
}
 /* ============== Admin: set Pro ============== */
app.post("/admin/setPro", async (req, res) => {
  const adminUser = await requireAdminAuth(req, res)
  if (!adminUser) return

  try {
    if (!db) {
      return res.status(500).json({
        ok: false,
        error: "Server missing Firebase credentials",
      })
    }

    const {
      uid,
      pro = true,
      planId = "pro_monthly",
      interval = "month",
      note = "manual admin activation",
    } = req.body || {}

    if (!uid) {
      return res.status(400).json({ ok: false, error: "Missing uid" })
    }

    // 🔹 Update user subscription
    const userRef = db.collection("users").doc(String(uid))
const userSnap = await userRef.get()

const base = Math.max(
  Date.now(),
  Number(userSnap.get("proUntil") || 0)
)

const proUntil = !!pro ? addInterval(base, interval) : null

await userRef.set(
  {
    pro: !!pro,
    planId,
    proUntil,
    proSetAt: admin.firestore.FieldValue.serverTimestamp(),
    lastPayment: {
      provider: "admin",
      note,
    },
  },
  { merge: true }
)


    //  AUDIT LOG (immutable, attributed)
    await logAdminAction({
      action: "set_pro",
      adminUid: adminUser.uid,
      targetUid: String(uid),
      meta: {
        pro: !!pro,
        planId,
        interval,
        note,
      },
    })

    return res.json({
      ok: true,
      uid: String(uid),
      pro: !!pro,
    })
  } catch (e) {
    console.error("admin/setPro error:", e)
    return res.status(500).json({
      ok: false,
      error: e?.message || "Server error",
    })
  }
})

/* ============== Pesapal: register IPN (ADMIN ONLY) ============== */
app.get('/pesapal/registerIPN', async (req, res) => {
  const adminUser = await requireAdminAuth(req, res)
  if (!adminUser) return

  try {
    const { token, url } = await pesaToken()
    const ipnUrl = `${serverOrigin(req)}/pesapal/ipn`

    const body = {
      url: ipnUrl,
      ipn_notification_type: 'GET',
    }

    const { data } = await axios.post(
      `${url}/api/URLSetup/RegisterIPN`,
      body,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
      }
    )

    // Optional audit log (recommended)
    await logAdminAction({
      action: 'register_ipn',
      adminUid: adminUser.uid,
      targetUid: null,
      meta: { ipnUrl },
    })

    return res.json({ ok: true, data })
  } catch (e) {
    return res.status(500).json({
      ok: false,
      error: e?.response?.data || e?.message || String(e),
    })
  }
})


/* ============== Pesapal: token test ============== */
app.get('/pesapal/tokenTest', authenticate, async (_req, res) => {
  try {
    const { base } = await pesaToken()
    res.json({ ok:true, base })
  } catch (e) {
    res.status(500).json({ ok:false, error: e?.response?.data || e?.message || String(e) })
  }
})

/* ============== Pesapal: Subscribe handler (authenticated) ============== */
async function subscribeHandler(req, res) {
  try {
    if (!db) return res.status(500).json({ ok:false, error:'Server missing Firebase credentials' })
    // require authenticated user
    if (!req.user || !req.user.uid) return res.status(401).json({ ok:false, error:'Unauthorized' })
    const uid = req.user.uid
    console.log("🟢 CREATE ORDER HIT", {
      time: new Date().toISOString(),
      uid,
      provider: req.user.firebase?.sign_in_provider,
      origin: req.headers.origin,
      path: req.originalUrl,
    })
    //  HARD BLOCK: never allow anonymous users to create orders
if (req.user.firebase?.sign_in_provider === 'anonymous') {
  return res.status(403).json({
    ok: false,
    error: 'Anonymous users must sign in before upgrading',
  })
}
    const { planId, email, first_name = '', last_name = '', country_code: rawCountry } = req.body || {}
    if (!planId || !AMOUNT_BY_PLAN[planId]) return res.status(400).json({ ok:false, error:'Unknown planId' })
    if (!PESA_IPN_ID) return res.status(500).json({ ok:false, error:'Server missing PESA_IPN_ID (register IPN first)' })

    const amount = AMOUNT_BY_PLAN[planId]
    const { token, base, url } = await pesaToken()

    // Merchant reference encodes plan & uid for IPN decoding
    const merchantRef = `sub_${planId}_${uid}_${Date.now()}`

    const country_code = normalizeCountryCode(rawCountry)

    const payload = {
      id: merchantRef,
      currency: CURRENCY,
      amount: Number(amount),
      description: `Getcertifyhq ${planId.replace('_',' ').toUpperCase()}`,
      callback_url: `${clean(PUBLIC_SITE_URL)}/app/upgrade?status=success`,
      cancellation_url: `${clean(PUBLIC_SITE_URL)}/app/upgrade?status=cancel`,
      notification_id: PESA_IPN_ID,
      billing_address: {
        email: email || 'guest@example.com',
        first_name,
        last_name,
        ...(country_code ? { country_code } : {})
      }
    }

    const { data } = await axios.post(
      `${url}/api/Transactions/SubmitOrderRequest`,
      payload,
      { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json' } }
    )

    const redirectUrl =
      data?.redirect_url || data?.order_instructions?.redirect_url || data?.payment_url || null

    if (!redirectUrl) {
      return res.status(502).json({ ok: false, error: 'Pesapal did not return redirect_url', provider_echo: { has_order_tracking_id: !!data?.order_tracking_id, keys: Object.keys(data || {}) } })
    }

    // Persist order record ENSURING we use merchantRef as id
    await db.collection('orders').doc(merchantRef).set({
      type: 'subscription', planId, amount, currency: CURRENCY, status: 'pending', createdAt: admin.firestore.FieldValue.serverTimestamp(), uid, provider: 'pesapal', orderTrackingId: data?.order_tracking_id || null, base
    }, { merge: true })

    return res.json({ ok: true, baseUsed: base, redirect_url: redirectUrl, order_tracking_id: data?.order_tracking_id, merchant_reference: merchantRef })
  } catch (e) {
    return res.status(500).json({ ok:false, error: e?.response?.data || e?.message || String(e) })
  }
}

// Require authentication + rate limit on subscribe/createOrder
app.post('/api/pesapal/subscribe', authenticate, pesapalLimiter, subscribeHandler)
app.post('/pesapal/createOrder',    authenticate, pesapalLimiter, subscribeHandler)

/* ============== Billing Reconcile (Authenticated) ============== */
app.post("/api/billing/reconcile", authenticate, async (req, res) => {
  try {
    const uid = req.user?.uid
    if (!uid) {
      return res.status(401).json({ ok: false, error: "Unauthorized" })
    }

    console.log("🧾 RECONCILE HIT", {
      uid,
      time: new Date().toISOString(),
    })

    const result = await reconcileForUser(uid)
    return res.json(result)
  } catch (e) {
    console.error("billing/reconcile error:", e)
    return res.status(500).json({
      ok: false,
      error: e?.message || "Server error",
    })
  }
})


/* ============== Pesapal: manual status check (optional) ============== */
app.get('/pesapal/getStatus', authenticate, async (req, res) => {
  try {
    const orderTrackingId = req.query.orderTrackingId
    if (!orderTrackingId) return res.status(400).json({ ok:false, error:'Missing orderTrackingId' })
    const { token, url } = await pesaToken()
    const { data } = await axios.get(`${url}/api/Transactions/GetTransactionStatus?orderTrackingId=${encodeURIComponent(orderTrackingId)}`, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' } })
    res.json({ ok:true, status: data })
  } catch (e) {
    res.status(500).json({ ok:false, error: e?.response?.data || e?.message || String(e) })
  }
})
/* ============== Pesapal: IPN (GET/POST) ============== */
async function handlePesaNotification(params, res) {
  try {
    if (params?.notification_id !== PESA_IPN_ID) {
      return res.status(403).json({ ok: false, error: "Invalid IPN source" })
    }
    const orderTrackingId = params?.OrderTrackingId || params?.orderTrackingId
    if (!orderTrackingId) {
      return res.status(400).json({ ok: false, error: "Missing OrderTrackingId" })
    }

    // Fetch status from Pesapal (server-to-server)
    const { token, url } = await pesaToken()
    const { data: status } = await axios.get(
      `${url}/api/Transactions/GetTransactionStatus?orderTrackingId=${encodeURIComponent(
        orderTrackingId
      )}`,
      { headers: { Authorization: `Bearer ${token}`, Accept: "application/json" } }
    )

    const paid = Number(status?.status_code) === 1 &&
    String(status?.payment_status_description || '') .toLowerCase() .includes('completed')
    const mr = String(status?.merchant_reference || "")
    let uid = null
    let planId = null

    if (db && mr) {
    const orderSnap = await db.collection("orders").doc(mr).get()
    if (orderSnap.exists) {
    const order = orderSnap.data()
    uid = order.uid || null
    planId = order.planId || null
   }
   }


   if (paid && (!uid || uid.startsWith("monthly_"))) {
   console.error(" IPN: Paid order but invalid UID resolution", { mr, uid })
   return res.status(500).json({ ok: false, error: "UID resolution failed" })
   }


    const amount = status?.amount
const currency = String(status?.currency || CURRENCY).toUpperCase()

/* ---------- PAYMENT AMOUNT VERIFICATION ---------- */
const expectedAmount = AMOUNT_BY_PLAN[planId]

if (paid && expectedAmount && Number(amount) !== Number(expectedAmount)) {
  console.error("⚠ Payment amount mismatch", {
    amount,
    expectedAmount,
    planId,
    merchantRef: mr
  })

  return res.status(400).json({ ok:false, error:"Payment amount mismatch" })
}

/* ---------- Continue if paid ---------- */
if (paid && db && uid && mr) {
      const orderRef = db.collection("orders").doc(mr)
      const orderSnap = await orderRef.get()

      if (!orderSnap.exists) {
        // Unknown order — persist record but do not upgrade user
        await db
          .collection("orders")
          .doc(mr)
          .set({ status: "failed_unknown_order", statusPayload: status }, { merge: true })
          .catch(() => {})
      } else {
        const userRef = db.collection("users").doc(uid)
        const userSnap = await userRef.get()

        //  If user profile doesn't exist yet, create a minimal one (race-proof)
        if (!userSnap.exists) {
          console.warn("⚠ Creating minimal user profile for paid order:", uid)

          await userRef.set(
            {
              uid,
              email: status?.billing_address?.email || null,
              planId: "free",
              pro: false,
              systemCreated: true,
              createdAt: admin.firestore.FieldValue.serverTimestamp(),
              updatedAt: admin.firestore.FieldValue.serverTimestamp(),
            },
            { merge: true }
          )
        }

        const finalPlanId = planId || amountToPlanId(amount) || "pro_monthly"
        const interval = INTERVAL_BY_PLAN[finalPlanId] || "month"
        const base = Math.max(
  Date.now(),
  Number(userSnap.get("proUntil") || 0)
)

const proUntil = addInterval(base, interval)


        //  Server is source of truth — always apply upgrade for paid orders
        await userRef.set(
          {
            pro: true,
            planId: finalPlanId,
            proUntil,
            proSetAt: admin.firestore.FieldValue.serverTimestamp(),
            lastPayment: {
              provider: "pesapal",
              orderTrackingId,
              merchant_reference: mr,
              amount,
              currency,
              status: status?.payment_status_description,
            },
          },
          { merge: true }
        )

        await orderRef.set(
          {
            status: "paid",
            paidAt: admin.firestore.FieldValue.serverTimestamp(),
            statusPayload: status,
          },
          { merge: true }
        )
      }
    } else {
      // Not paid / missing data — record failure
      await db
        ?.collection("orders")
        .doc(mr || orderTrackingId)
        .set({ status: "failed", statusPayload: status }, { merge: true })
        .catch(() => {})
    }

    if (params?.OrderNotificationType === "IPNCHANGE") {
      return res.json({
        orderNotificationType: "IPNCHANGE",
        orderTrackingId,
        orderMerchantReference: status?.merchant_reference || "",
        status: 200,
      })
    }

    return res.json({ ok: true, status })
  } catch (e) {
    const err = e?.response?.data || e?.message || String(e)
    return res.status(500).json({ ok: false, error: err })
  }
}

app.get("/pesapal/ipn", ipnLimiter, (req, res) =>
  handlePesaNotification(req.query, res)
)
app.post("/pesapal/ipn", ipnLimiter, (req, res) =>
  handlePesaNotification(req.body, res)
)

/* ============== Admin Verification (break-glass) ============== */
 app.post('/api/admin/verify', adminVerifyLimiter, async (req, res) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(404).json({ ok: false })
  }

  const { idToken, password } = req.body || {}
  if (!idToken || password !== ADMIN_PASSWORD) {
    return res.status(403).json({ ok: false })
  }

  const decoded = await admin.auth().verifyIdToken(idToken, true)

  await admin.auth().setCustomUserClaims(decoded.uid, { admin: true })

await db.collection("users").doc(decoded.uid).set({
  isAdmin: true
}, { merge: true })
  await admin.auth().revokeRefreshTokens(decoded.uid)

  res.json({ ok: true })
})


/* ============== Org custom domain verification (secured) ============== */


// Rate limiter: max 5 requests per minute per user
const orgVerifyLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { ok: false, error: 'Too many verification attempts, try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
})

app.get('/api/org/:orgId/verify-domain', authenticate, orgVerifyLimiter, async (req, res) => {
  try {
    const { orgId } = req.params
    if (!db) return res.status(500).json({ ok: false, error: 'Server missing Firebase credentials' })

    const orgSnap = await db.collection('orgs').doc(orgId).get()
    if (!orgSnap.exists) return res.status(404).json({ ok: false, error: 'Organization not found' })

    const orgData = orgSnap.data()

    // Ownership check
    if (orgData.ownerUid !== req.user.uid) {
      return res.status(403).json({ ok: false, error: 'Forbidden: you do not own this organization' })
    }
   const rawDomain = orgData.customVerifyDomain
const domain = normalizeDomain(rawDomain)
if (domain.split('.').length < 3) {
  return res.status(400).json({
    ok:false,
    error:'Use a subdomain (example: verify.yourschool.com)'
  })
}

if (!domain) {
  return res.status(400).json({ ok: false, error: 'No custom domain set for this org' })
}

//  Prevent domain change if already verified
if (
  orgData.domainVerified === true &&
  orgData.customVerifyDomain &&
  normalizeDomain(orgData.customVerifyDomain) !== domain
) {
  return res.status(400).json({
    ok: false,
    error: 'Domain is locked. Remove verification before changing domain.'
  })
}

   //  Prevent domain reuse across organizations
  const existing = await db
  .collection('orgs')
  .where('customVerifyDomain', '==', domain)
  .get()

  if (!existing.empty && existing.docs[0].id !== orgId) {
  return res.status(400).json({
    ok: false,
    error: 'Domain already in use by another organization'
  })
 }
    

    // Attempt CNAME lookup then TXT fallback
    let verified = false
    let cnames = []
    try {
      cnames = await Promise.race([
  dns.resolveCname(domain),
  new Promise((_, reject) =>
    setTimeout(() => reject(new Error('DNS lookup timeout')), 4000)
  )
 ])
      verified = cnames.includes(VERIFY_CNAME_TARGET)
    } catch (err) {
      if (!['ENODATA', 'ENOTFOUND'].includes(err.code)) throw err
    }

   if (!verified) {
  try {
    const txts = await dns.resolveTxt(domain)
    const flat = txts.flat().map(s => s.toString().trim())

    const expected = `certify-verify=org:${orgId}`
    if (flat.includes(expected)) verified = true
  } catch (e) {
    // ignore TXT errors
  }
}

   await db.collection('orgs').doc(orgId).set({
  customVerifyDomain: domain,
  domainVerified: verified,
  domainVerifiedAt: verified ? admin.firestore.FieldValue.serverTimestamp() : null
}, { merge: true })
    res.json({ ok: true, domain, verified, cnames })

  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) })
  }
})

app.use((err, req, res, next) => {
  console.error('UNHANDLED ERROR:', err)
  res.status(500).json({ ok: false, error: 'Internal server error' })
})


/* ============== Start ============== */
app.listen(PORT, () => {
  console.log(`verify service listening on :${PORT}`)
  console.log(`Allowed origins: ${allowList.join(', ') || '(none)'}`)
  console.log(`NODE_ENV is: ${process.env.NODE_ENV || 'development'}`)
})


















