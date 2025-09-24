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
  PESA_IPN_ID,

  // Pricing (server-authoritative)
  PRICE_MONTHLY_USD = '15',
  PRICE_ANNUAL_USD  = '148',
  PRICE_MONTHLY_KES = '1500',
  PRICE_ANNUAL_KES  = '14750',
  PRICE_MONTHLY_UGX = '55000',
  PRICE_ANNUAL_UGX  = '539000'
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

/* ---------- Pricing (server-authoritative) ---------- */
// NEW: server is source of truth for amounts, the client only sends {period, currency}
const PRICES = {
  monthly: {
    USD: Number(PRICE_MONTHLY_USD) || 15,
    KES: Number(PRICE_MONTHLY_KES) || 1500,
    UGX: Number(PRICE_MONTHLY_UGX) || 55000
  },
  annual: {
    USD: Number(PRICE_ANNUAL_USD) || 148,
    KES: Number(PRICE_ANNUAL_KES) || 14750,
    UGX: Number(PRICE_ANNUAL_UGX) || 539000
  }
}
const SUPPORTED_CURRENCIES = ['USD','KES','UGX']

/* ---------- Express & Security ---------- */
const app = express()
app.set('trust proxy', true) // NEW: respect x-forwarded headers
app.use(express.json({ limit: '2mb' }))
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}))
// Optional: HSTS if behind HTTPS
app.use((req, res, next) => {
  if (req.secure || (req.headers['x-forwarded-proto'] || '').toString().includes('https')) {
    res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains')
  }
  next()
})
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
// NEW: turn CORS errors into JSON instead of crashing
app.use((err, req, res, next) => {
  if (err && err.message === 'Not allowed by CORS') {
    return res.status(403).json({ ok:false, error:'cors_rejected_origin' })
  }
  return next(err)
})
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
  const proto = (req.headers['x-forwarded-proto'] || '').toString().split(',')[0] || (req.secure ? 'https' : 'http')
  const host = req.headers.host
  return `${proto}://${host}`
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
      <p>Pricing: <a href="/pricing">/pricing</a> · <a href="/pricing/currencies">/pricing/currencies</a></p>
      <p>Email link endpoint: <code>POST /makeEmailLink</code></p>
      <p>Pesapal health: <a href="/pesapal/health">/pesapal/health</a></p>
    </body></html>
  `)
})

/* ---------- Pricing endpoints (optional, helpful for FE) ---------- */
// NEW: expose currencies & price table for the frontend
app.get(['/pricing/currencies'], (req, res) => {
  setCorsForHealth(req, res)
  res.json({ ok:true, currencies: SUPPORTED_CURRENCIES })
})
app.get(['/pricing'], (req, res) => {
  setCorsForHealth(req, res)
  res.json({ ok:true, prices: PRICES })
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
    headers: { Authorization: `Bearer ${FLW_SECRET}` },
    timeout: 15000 // NEW
  })
  const d = vr?.data?.data
  if (!d) return { ok:false, status:400, error:'invalid_verify_response' }

  const statusOk   = d.status === 'successful'
  const currencyOk = ['USD','KES','UGX'].includes(String(d.currency || '').toUpperCase()) // NEW: permit regional
  const txRefOk    = String(d.tx_ref || '') === String(tx_ref)
  const refUid     = parseUidFromTxRef(d.tx_ref)

  if (!statusOk || !currencyOk || !txRefOk) {
    return { ok:false, status:400, reason:'verify_failed', got:{ status:d.status, currency:d.currency, tx_ref:d.tx_ref } }
  }
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
const PESA_KEY    = clean(PESA_CONSUMER_KEY)
const PESA_SECRET = clean(PESA_CONSUMER_SECRET)
const PESA_MODE   = (PESA_BASE || 'demo').toLowerCase() // 'demo' | 'live'
const PESA_DEMO   = 'https://cybqa.pesapal.com/pesapalv3'
const PESA_LIVE   = 'https://pay.pesapal.com/v3'
const PESA_URL    = PESA_MODE === 'live' ? PESA_LIVE : PESA_DEMO

// Backoff helper (NEW)
const delay = (ms) => new Promise(r => setTimeout(r, ms))
async function withBackoff(fn, max = 2, base = 300) {
  let i = 0
  while (true) {
    try { return await fn(i) } catch (e) {
      if (i >= max) throw e
      const ms = Math.floor(base * Math.pow(2, i) * (1 + Math.random() * 0.2))
      await delay(ms); i++
    }
  }
}

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
      { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json' }, timeout: 15000 }
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
    if (!PESA_IPN_ID) return bad(res, 500, 'missing_pesa_ipn_id')

    const token = await pesaToken()
    const {
      // ignore client 'amount'; compute server-side:
      currency = 'KES',         // KES | UGX | USD
      period = 'monthly',       // 'monthly' | 'annual'
      email,
      name,                     // single full name from UI
      first_name = '',          // fallback
      last_name  = ''
    } = req.body || {}

    const cur = String(currency).toUpperCase()
    if (!SUPPORTED_CURRENCIES.includes(cur)) return bad(res, 400, 'invalid_currency')
    const per = period === 'annual' ? 'annual' : 'monthly'
    const amount = PRICES[per][cur]
    if (!Number.isFinite(+amount) || +amount < 1) return bad(res, 500, 'price_unavailable')

    const uid = decoded.uid
    const merchantRef = `certify_${uid}_${Date.now()}`
    const [fn, ln] = (String(name || '').trim().split(/\s+/).length >= 2)
      ? [String(name).trim().split(/\s+/).slice(0, -1).join(' '), String(name).trim().split(/\s+/).slice(-1).join(' ')]
      : [first_name, last_name]

    const body = {
      id: merchantRef,
      currency: cur,
      amount: Number(amount),
      description: `Certify pro (${per})`,
      callback_url: `${clean(PUBLIC_SITE_URL)}/upgrade?pesapal=1`,
      notification_id: PESA_IPN_ID,
      billing_address: {
        email_address: email || 'guest@example.com',
        first_name: fn || first_name || '',
        last_name:  ln || last_name  || '',
        country_code: cur === 'USD' ? 'US' : 'UG' // light hint only
      }
    }

    // NEW: persist pending order (allows verification on IPN)
    await db.collection('payments').doc(merchantRef).set({
      provider: 'pesapal',
      uid,
      period: per,
      currency: cur,
      expectedAmount: Number(amount),
      status: 'pending',
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true })

    const { data } = await withBackoff(
      async () => axios.post(
        `${PESA_URL}/api/Transactions/SubmitOrderRequest`,
        body,
        { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json' }, timeout: 20000 }
      ),
      2, 350
    )

    const redirect_url = data?.data?.redirect_url || data?.redirect_url || data?.payment_url || data?.redirectUrl || null
    if (!redirect_url) return bad(res, 502, 'no_redirect_url')
    res.json({ ok: true, redirect_url, merchant_reference: merchantRef })
  } catch (e) {
    const msg = e?.message === 'invalid_token' ? 'unauthorized' : (e?.response?.data?.error || 'order_create_failed')
    res.status(e?.message === 'invalid_token' ? 401 : 500).json({ ok:false, error: msg })
  }
})

async function pesaFetchStatus(orderTrackingId) {
  const token = await pesaToken()
  const { data } = await withBackoff(
    async () => axios.get(
      `${PESA_URL}/api/Transactions/GetTransactionStatus?orderTrackingId=${encodeURIComponent(orderTrackingId)}`,
      { headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' }, timeout: 15000 }
    ),
    2, 300
  )
  return data?.data || data
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

    if (db && uid) {
      // NEW: cross-check the pending order
      const payRef = db.collection('payments').doc(mr)
      const snap = await payRef.get()
      const exp = snap.exists ? snap.data() : null

      // If we have an expected record, validate currency/amount before granting Pro
      const currencyOk = exp ? String(status?.currency || '').toUpperCase() === String(exp.currency || '').toUpperCase() : true
      const amountOk   = exp ? Number(status?.amount || 0) >= Number(exp.expectedAmount || 0) : true

      if (paid && currencyOk && amountOk) {
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

        await payRef.set({
          status: 'paid',
          paidAt: admin.firestore.FieldValue.serverTimestamp(),
          orderTrackingId,
          amount: status?.amount,
          currency: status?.currency
        }, { merge: true })
      } else {
        // record failed/invalid for troubleshooting
        await payRef.set({
          status: paid ? 'mismatch' : 'failed',
          lastStatus: status || null,
          lastUpdateAt: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true })
      }
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
  } catch (e) {
    return res.status(500).json({ ok:false, error:'ipn_handler_failed' })
  }
}

app.get('/pesapal/ipn', (req, res) => handlePesaNotification(req.query, res))
app.post('/pesapal/ipn', (req, res) => handlePesaNotification(req.body, res))

/* ---------- Start ---------- */
app.use((req, res) => bad(res, 404, 'not_found'))
app.listen(PORT, () => console.log(`✅ Certify verify service listening on :${PORT}`))
