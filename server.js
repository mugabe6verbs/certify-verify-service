// server.js — Certify backend (Pesapal + optional Flutterwave)
// Node 18+ (global fetch available). Run: node server.js

import express from 'express'
import axios from 'axios'
import admin from 'firebase-admin'
import cors from 'cors'
import helmet from 'helmet'
import compression from 'compression'
import rateLimit from 'express-rate-limit'
import morgan from 'morgan'

/* ---------- ENV ---------- */
const {
  PORT = 8080,

  // Firebase Admin
  FIREBASE_PROJECT_ID,
  FIREBASE_CLIENT_EMAIL,
  FIREBASE_PRIVATE_KEY,

  // CORS + site
  ALLOW_ORIGINS = 'http://localhost:5173,https://certificate-generator-345be.web.app,https://certificate-generator-345be.firebaseapp.com',
  PUBLIC_SITE_URL = 'https://certificate-generator-345be.web.app',

  // Flags / admin
  ALLOW_MANUAL_PRO,
  ADMIN_TOKEN,

  // (Optional) Flutterwave
  FLW_SECRET,

  // Pesapal
  PESA_CONSUMER_KEY,
  PESA_CONSUMER_SECRET,
  PESA_BASE = 'demo',  // 'demo' | 'live'
  PESA_IPN_ID
} = process.env

const clean = (s) => (s || '').trim().replace(/^"(.*)"$/, '$1').replace(/^'(.*)'$/, '$1')
const mask = (s) => (s && s.length >= 8 ? s.slice(0, 4) + '…' + s.slice(-4) : '(empty)')

/* ---------- Firebase Admin ---------- */
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

/* ---------- Express & Security ---------- */
const app = express()
app.use(express.json({ limit: '2mb' }))
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }))
app.use(compression())
app.use(morgan('tiny'))

const allowList = (ALLOW_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean)
const corsMw = cors({
  origin(origin, cb) {
    if (!origin || allowList.includes(origin)) return cb(null, true) // allow server-to-server and whitelisted origins
    return cb(new Error('Not allowed by CORS'))
  },
  methods: ['GET','POST','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','X-Admin-Token','x-admin-token'],
  optionsSuccessStatus: 204
})
app.use(corsMw)
app.options('*', corsMw)

// Basic rate limit (tune as needed)
app.use(rateLimit({ windowMs: 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false }))

/* Small helper to ensure health endpoints always send ACAO */
function setCorsForHealth(req, res) {
  const origin = req.headers.origin
  if (!origin || allowList.includes(origin)) {
    res.set('Access-Control-Allow-Origin', origin || '*')
    res.set('Vary', 'Origin')
  }
}

/* ---------- Helpers ---------- */
function bad(res, code, msg, extra = {}) {
  return res.status(code).json({ ok: false, error: msg, ...extra })
}

async function requireAuth(req, res) {
  const authz = req.headers.authorization || ''
  const m = authz.match(/^Bearer\s+(.+)$/i)
  if (!m) throw new Error('missing_bearer')
  const token = m[1]
  try {
    const decoded = await admin.auth().verifyIdToken(token)
    return decoded // { uid, ... }
  } catch (e) {
    throw new Error('invalid_token')
  }
}

function isAdmin(req) {
  const token = req.headers['x-admin-token'] || req.headers['X-Admin-Token']
  return ADMIN_TOKEN && token === ADMIN_TOKEN
}

function serverOrigin(req) {
  const xfProto = (req.headers['x-forwarded-proto'] || '').toString().split(',')[0] || 'https'
  const host = req.headers.host
  return `${xfProto}://${host}`
}

/* ---------- Health & Home ---------- */
app.get(['/health','/api/health'], (req, res) => {
  setCorsForHealth(req, res)
  res.json({
    ok: true,
    projectId: FIREBASE_PROJECT_ID || null,
    hasFirebaseCreds,
    allowList
  })
})

app.get('/', (req, res) => {
  const maskedSA = (FIREBASE_CLIENT_EMAIL || '').replace(/(.{3}).+(@.+)/, '$1***$2')
  res.type('html').send(`
    <html><body style="font-family:system-ui;padding:16px">
      <h2>Certify Verify Service</h2>
      <ul>
        <li>Project: <code>${FIREBASE_PROJECT_ID || '—'}</code></li>
        <li>Service account: <code>${maskedSA || '—'}</code></li>
        <li>Firebase creds set: <strong style="color:${hasFirebaseCreds?'green':'crimson'}">${hasFirebaseCreds}</strong></li>
        <li>Allowed origins: ${allowList.map(o=>`<code>${o}</code>`).join(', ') || '—'}</li>
        <li>ALLOW_MANUAL_PRO: <code>${String(ALLOW_MANUAL_PRO_ENV)}</code></li>
      </ul>
      <p>Health: <a href="/health">/health</a></p>
      <p>Email link endpoint: <code>POST /makeEmailLink</code></p>
      <p>Pesapal health: <a href="/pesapal/health">/pesapal/health</a></p>
    </body></html>
  `)
})

/* ---------- Passwordless email link ---------- */
app.post(['/makeEmailLink','/api/makeEmailLink','/admin/makeEmailLink'], async (req, res) => {
  try {
    if (!db) return bad(res, 500, 'server_missing_firebase')
    const { email } = req.body || {}
    if (!email) return bad(res, 400, 'missing_email')
    const actionCodeSettings = { url: `${clean(PUBLIC_SITE_URL)}/finish-signin`, handleCodeInApp: true }
    const link = await admin.auth().generateSignInWithEmailLink(String(email), actionCodeSettings)
    res.json({ ok:true, link })
  } catch (e) {
    res.status(500).json({ ok:false, error: 'email_link_failed' })
  }
})

/* ---------- Flutterwave (optional; locked down) ---------- */
const hasFlwSecret = !!FLW_SECRET

function parseUidFromTxRef(txref) {
  const m = String(txref || '').match(/^certify_([^_]+)_\d+/)
  return m ? m[1] : null
}

async function verifyFlwAndActivate({ id, tx_ref }, callerUid) {
  if (!id || !tx_ref) return { ok:false, status:400, error:'missing_id_or_txref' }
  if (!hasFlwSecret)    return { ok:false, status:500, error:'server_missing_flw_secret' }
  if (!db)              return { ok:false, status:500, error:'server_missing_firebase' }

  const vr = await axios.get(`https://api.flutterwave.com/v3/transactions/${encodeURIComponent(id)}/verify`, {
    headers: { Authorization: `Bearer ${FLW_SECRET}` }
  })
  const d = vr?.data?.data
  if (!d) return { ok:false, status:400, error:'invalid_verify_response' }

  const statusOk   = d.status === 'successful'
  const currencyOk = String(d.currency || '').toUpperCase() === 'USD'
  const txRefOk    = String(d.tx_ref || '') === String(tx_ref)
  const refUid     = parseUidFromTxRef(d.tx_ref)

  if (!statusOk || !currencyOk || !txRefOk) {
    return { ok:false, status:400, reason:'verify_failed', got:{ status:d.status, currency:d.currency, tx_ref:d.tx_ref } }
  }
  // Ensure the paying user becomes Pro — use the uid inside tx_ref or the authenticated caller
  const uid = refUid || callerUid
  if (!uid) return { ok:false, status:400, error:'cannot_resolve_uid' }

  await db.collection('users').doc(String(uid)).set({
    pro: true,
    proSetAt: admin.firestore.FieldValue.serverTimestamp(),
    lastPayment: {
      provider: 'flutterwave',
      id: String(d.id),
      tx_ref: d.tx_ref,
      amount: d.amount,
      currency: d.currency,
      status: d.status,
      customer: d.customer || null
    }
  }, { merge: true })

  return { ok:true, uid, tx_ref, amount:d.amount, currency:d.currency }
}

// Require Authorization for verifyFlw (prevents spoofed uid flips)
app.post(['/verifyFlw','/api/verifyFlw','/admin/verifyFlw'], async (req, res) => {
  try {
    const decoded = await requireAuth(req, res) // throws on fail
    const { id, tx_ref } = req.body || {}
    const out = await verifyFlwAndActivate({ id, tx_ref }, decoded.uid)
    if (!out.ok) return res.status(out.status || 500).json(out)
    res.json(out)
  } catch {
    res.status(401).json({ ok:false, error:'unauthorized' })
  }
})

/* ---------- Manual Pro (dev/test) ---------- */
async function isManualProEnabled() {
  if (ALLOW_MANUAL_PRO_ENV) return true
  if (!db) return false
  try {
    const snap = await db.collection('config').doc('flags').get()
    return !!(snap.exists && snap.get('allowManualPro') === true)
  } catch { return false }
}

app.post(['/manualPro','/api/manualPro','/admin/manualPro'], async (req, res) => {
  try {
    if (!db) return bad(res, 500, 'server_missing_firebase')
    const decoded = await requireAuth(req, res) // uses Authorization header now
    if (!(await isManualProEnabled())) return bad(res, 403, 'manual_pro_disabled')
    await db.collection('users').doc(decoded.uid).set({
      pro: true,
      proSetAt: admin.firestore.FieldValue.serverTimestamp(),
      lastPayment: { provider: 'manual' }
    }, { merge: true })
    res.json({ ok:true, uid: decoded.uid })
  } catch {
    res.status(401).json({ ok:false, error:'unauthorized' })
  }
})

/* ---------- Admin rescue ---------- */
function requireAdmin(req, res) {
  if (!ADMIN_TOKEN) { bad(res, 500, 'server_missing_admin_token'); return false }
  const token = req.headers['x-admin-token']
  if (!token || token !== ADMIN_TOKEN) { bad(res, 403, 'forbidden_admin'); return false }
  return true
}

app.post('/admin/setPro', async (req, res) => {
  try {
    if (!requireAdmin(req, res)) return
    if (!db) return bad(res, 500, 'server_missing_firebase')
    const { uid, pro = true, note = 'admin setPro' } = req.body || {}
    if (!uid) return bad(res, 400, 'missing_uid')
    await db.collection('users').doc(String(uid)).set({
      pro: !!pro,
      proSetAt: admin.firestore.FieldValue.serverTimestamp(),
      lastPayment: { provider:'admin', note }
    }, { merge: true })
    res.json({ ok:true, uid:String(uid), pro:!!pro })
  } catch {
    res.status(500).json({ ok:false, error:'admin_setpro_failed' })
  }
})

/* ---------- Pesapal ---------- */
const PESA_KEY  = clean(PESA_CONSUMER_KEY)
const PESA_SECRET = clean(PESA_CONSUMER_SECRET)
const PESA_MODE = (PESA_BASE || 'demo').toLowerCase() // 'demo' | 'live'
const PESA_DEMO = 'https://cybqa.pesapal.com/pesapalv3'
const PESA_LIVE = 'https://pay.pesapal.com/v3'
const PESA_URL  = PESA_MODE === 'live' ? PESA_LIVE : PESA_DEMO

// lightweight token cache (avoid RequestToken spam)
let pesaTok = { token: null, expAt: 0 }
async function pesaToken() {
  const now = Date.now()
  if (pesaTok.token && pesaTok.expAt > now + 5000) return pesaTok.token
  if (!PESA_KEY || !PESA_SECRET) throw new Error('missing_pesapal_keys')
  const { data } = await axios.post(
    `${PESA_URL}/api/Auth/RequestToken`,
    { consumer_key: PESA_KEY, consumer_secret: PESA_SECRET },
    { headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, timeout: 15000 }
  )
  const tok = data?.token
  if (!tok) throw new Error('no_token_in_response')
  pesaTok = { token: tok, expAt: now + 20 * 60 * 1000 } // ~20 min TTL (tune if API returns expires_in)
  return tok
}

app.get('/pesapal/health', (req, res) => {
  setCorsForHealth(req, res)
  res.json({
    ok: !!(PESA_KEY && PESA_SECRET),
    base: PESA_MODE,
    url: PESA_URL,
    keyPreview: mask(PESA_KEY),
    secretPreview: mask(PESA_SECRET),
    hasKeys: !!(PESA_KEY && PESA_SECRET),
    hasIpn: !!PESA_IPN_ID
  })
})

// Admin-only: register IPN URL
app.post('/pesapal/registerIPN', async (req, res) => {
  try {
    if (!isAdmin(req)) return bad(res, 403, 'forbidden_admin')
    const token = await pesaToken()
    const ipnUrl = req.body?.url || `${serverOrigin(req)}/pesapal/ipn`
    const { data } = await axios.post(
      `${PESA_URL}/api/URLSetup/RegisterIPN`,
      { url: ipnUrl, ipn_notification_type: 'GET' },
      { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json' } }
    )
    res.json({ ok: true, ...data }) // data.ipn_id
  } catch {
    res.status(500).json({ ok:false, error: 'ipn_register_failed' })
  }
})

// Create order (REQUIRES Authorization; uid is taken from ID token)
app.post('/pesapal/createOrder', async (req, res) => {
  try {
    const decoded = await requireAuth(req, res)
    if (!db) return bad(res, 500, 'server_missing_firebase')
    const token = await pesaToken()
    const {
      amount = 15,
      currency = 'KES',     // ensure your Pesapal account supports the chosen currency
      email,
      first_name = '',
      last_name = '',
      plan = 'pro',
      period = 'monthly'
    } = req.body || {}

    if (!PESA_IPN_ID) return bad(res, 500, 'missing_pesa_ipn_id')
    if (!Number.isFinite(+amount) || +amount < 1) return bad(res, 400, 'invalid_amount')
    if (!['KES','UGX','USD'].includes(String(currency).toUpperCase())) return bad(res, 400, 'invalid_currency')

    const uid = decoded.uid
    const merchantRef = `certify_${uid}_${Date.now()}`
    const body = {
      id: merchantRef,
      currency: String(currency).toUpperCase(),
      amount: Number(amount),
      description: `Certify ${plan} (${period})`,
      callback_url: `${clean(PUBLIC_SITE_URL)}/upgrade`,
      notification_id: PESA_IPN_ID,
      billing_address: {
        email_address: email || 'guest@example.com',
        first_name,
        last_name,
        country_code: 'UG'
      }
    }

    const { data } = await axios.post(
      `${PESA_URL}/api/Transactions/SubmitOrderRequest`,
      body,
      { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json' } }
    )

    const redirect_url = data?.redirect_url || data?.payment_url || data?.redirectUrl || null
    if (!redirect_url) return bad(res, 502, 'no_redirect_url')
    res.json({ ok: true, redirect_url, merchant_reference: merchantRef })
  } catch (e) {
    res.status(401).json({ ok:false, error: e?.message === 'invalid_token' ? 'unauthorized' : 'order_create_failed' })
  }
})

async function pesaFetchStatus(orderTrackingId) {
  const token = await pesaToken()
  const { data } = await axios.get(
    `${PESA_URL}/api/Transactions/GetTransactionStatus?orderTrackingId=${encodeURIComponent(orderTrackingId)}`,
    { headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' } }
  )
  return data
}

async function handlePesaNotification(params, res) {
  try {
    const orderTrackingId = params?.OrderTrackingId || params?.orderTrackingId
    if (!orderTrackingId) return bad(res, 400, 'missing_order_tracking_id')

    const status = await pesaFetchStatus(orderTrackingId)
    const mr = String(status?.merchant_reference || '')
    const match = mr.match(/^certify_(.+?)_/)
    const uid = match ? match[1] : null

    // Pesapal demo/live codes differ; treat "1" or a success string as paid
    const paid =
      status?.status_code === 1 ||
      /^(COMPLETED|PAID|SUCCESS|CONFIRMED)$/i.test(status?.payment_status || status?.payment_status_description || '')

    if (db && uid && paid) {
      await db.collection('users').doc(uid).set({
        pro: true,
        proSetAt: admin.firestore.FieldValue.serverTimestamp(),
        lastPayment: {
          provider: 'pesapal',
          orderTrackingId,
          merchant_reference: mr,
          amount: status?.amount,
          currency: status?.currency,
          status: status?.payment_status_description || status?.payment_status || 'SUCCESS'
        }
      }, { merge: true })
    }

    if (params?.OrderNotificationType === 'IPNCHANGE') {
      return res.json({
        orderNotificationType: 'IPNCHANGE',
        orderTrackingId,
        orderMerchantReference: status?.merchant_reference || '',
        status: 200
      })
    }
    return res.json({ ok:true })
  } catch {
    return res.status(500).json({ ok:false, error:'ipn_handler_failed' })
  }
}

app.get('/pesapal/ipn', (req, res) => handlePesaNotification(req.query, res))
app.post('/pesapal/ipn', (req, res) => handlePesaNotification(req.body, res))

/* ---------- Start ---------- */
app.use((req, res) => bad(res, 404, 'not_found'))
app.listen(PORT, () => console.log(`✅ Certify verify service listening on :${PORT}`))
