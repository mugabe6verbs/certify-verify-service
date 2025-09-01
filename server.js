// server.js (ESM)
// package.json must have: { "type": "module", "scripts": { "start": "node server.js" } }
import express from 'express'
import axios from 'axios'
import admin from 'firebase-admin'
import cors from 'cors'

/* ===== Env ===== */
const {
  PORT = 8080,

  // Firebase Admin
  FIREBASE_PROJECT_ID,
  FIREBASE_CLIENT_EMAIL,
  FIREBASE_PRIVATE_KEY,

  // CORS + site
  ALLOW_ORIGINS = 'http://localhost:5173,https://certificate-generator-345be.web.app,https://certificate-generator-345be.firebaseapp.com,https://certify-verify-service-2.onrender.com',
  PUBLIC_SITE_URL = 'https://certificate-generator-345be.web.app',

  // Flags
  ALLOW_MANUAL_PRO,
  ADMIN_TOKEN,

  // Flutterwave (optional)
  FLW_SECRET,

  // Pesapal
  PESA_CONSUMER_KEY,
  PESA_CONSUMER_SECRET,
  PESA_BASE = 'demo',
  PESA_IPN_ID
} = process.env

/* ===== Helpers ===== */
const clean = (s) => (s || '').trim().replace(/^"(.*)"$/, '$1').replace(/^'(.*)'$/, '$1')
const mask  = (s) => (s && s.length >= 8 ? s.slice(0,4)+'…'+s.slice(-4) : '(empty)')
function serverOrigin(req) {
  const xfProto = (req.headers['x-forwarded-proto'] || '').toString().split(',')[0] || 'https'
  const host = req.headers.host
  return `${xfProto}://${host}`
}

/* ===== Firebase Admin ===== */
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

/* ===== Pesapal config (for early health) ===== */
const PESA_KEY    = clean(PESA_CONSUMER_KEY)
const PESA_SECRET = clean(PESA_CONSUMER_SECRET)
const PESA_MODE   = (PESA_BASE || 'demo').toLowerCase() // 'demo' | 'live'
const PESA_DEMO   = 'https://cybqa.pesapal.com/pesapalv3'
const PESA_LIVE   = 'https://pay.pesapal.com/v3'
const PESA_URL    = PESA_MODE === 'live' ? PESA_LIVE : PESA_DEMO

/* ===== App ===== */
const app = express()

/* --- EARLY health endpoints (pre-body-parser & pre-CORS) --- */
app.get('/pesapal/health', (_req, res) => {
  res.json({
    ok: true,
    base: PESA_MODE,
    url: PESA_URL,
    keyPreview: mask(PESA_KEY),
    secretPreview: mask(PESA_SECRET),
    hasKeys: !!(PESA_KEY && PESA_SECRET),
    hasIpn: !!PESA_IPN_ID
  })
})

app.get(['/health','/api/health'], (_req, res) => {
  res.json({
    ok: true,
    projectId: FIREBASE_PROJECT_ID || null,
    hasFirebaseCreds: !!hasFirebaseCreds
  })
})

/* --- EARLY IPN register (GET/POST; empty bodies allowed) --- */
app.all('/pesapal/registerIPN', async (req, res) => {
  try {
    if (!PESA_KEY || !PESA_SECRET) {
      return res.status(500).json({ ok:false, error:'Missing PESA_CONSUMER_KEY/SECRET' })
    }
    const origin = serverOrigin(req)
    const ipnUrl = req.query?.url || `${origin}/pesapal/ipn`

    const tokenResp = await axios.post(
      `${PESA_URL}/api/Auth/RequestToken`,
      { consumer_key: PESA_KEY, consumer_secret: PESA_SECRET },
      { headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, timeout: 15000 }
    )
    const token = tokenResp?.data?.token
    if (!token) throw new Error(`No token in response: ${JSON.stringify(tokenResp?.data)}`)

    const { data } = await axios.post(
      `${PESA_URL}/api/URLSetup/RegisterIPN`,
      { url: ipnUrl, ipn_notification_type: 'GET' },
      { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json' } }
    )
    // { ipn_id, url, ipn_notification_type }
    res.json({ ok: true, ...data })
  } catch (e) {
    res.status(500).json({ ok:false, error: e?.response?.data || e?.message || String(e) })
  }
})

/* --- Parse JSON only for methods that carry a body --- */
app.use((req, res, next) => {
  const m = req.method
  if (m === 'POST' || m === 'PUT' || m === 'PATCH' || m === 'DELETE') {
    return express.json({ limit: '2mb' })(req, res, next)
  }
  return next()
})

/* ===== CORS ===== */
const allowList = (ALLOW_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean)
const corsOptions = {
  origin(origin, cb) {
    if (!origin || allowList.includes(origin)) return cb(null, true)
    return cb(new Error('Not allowed by CORS'))
  },
  methods: ['GET','POST','OPTIONS','PUT','PATCH','DELETE'],
  allowedHeaders: ['Content-Type','Authorization','X-Admin-Token','x-admin-token'],
  optionsSuccessStatus: 204
}
app.options('*', cors(corsOptions))
app.use(cors(corsOptions))

/* --- JSON error handler (no HTML error pages) --- */
app.use((err, _req, res, _next) => {
  if (err) return res.status(400).json({ ok:false, error: err.message || 'Bad Request' })
})

/* ===== Home ===== */
app.get('/', (_req, res) => {
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
      <p>Pesapal health: <a href="/pesapal/health">/pesapal/health</a></p>
      <p><strong>Register IPN:</strong> <a href="/pesapal/registerIPN">/pesapal/registerIPN</a></p>
    </body></html>
  `)
})

/* ===== Debug: list mounted routes (helps confirm what’s live) ===== */
app.get('/debug/routes', (_req, res) => {
  const routes = []
  app._router.stack.forEach((m) => {
    if (m.route && m.route.path) {
      routes.push({ methods: Object.keys(m.route.methods), path: m.route.path })
    } else if (m.name === 'router' && m.handle?.stack) {
      m.handle.stack.forEach((h) => {
        if (h.route && h.route.path) {
          routes.push({ methods: Object.keys(h.route.methods), path: h.route.path })
        }
      })
    }
  })
  res.json({ ok:true, routes })
})

/* ===== Email link (passwordless) ===== */
app.post(['/makeEmailLink','/api/makeEmailLink','/admin/makeEmailLink'], async (req, res) => {
  try {
    if (!db) return res.status(500).json({ ok:false, error:'Server missing Firebase credentials' })
    const { email } = req.body || {}
    if (!email) return res.status(400).json({ ok:false, error:'Missing email' })
    const actionCodeSettings = { url: `${clean(PUBLIC_SITE_URL)}/finish-signin`, handleCodeInApp: true }
    const link = await admin.auth().generateSignInWithEmailLink(String(email), actionCodeSettings)
    res.json({ ok:true, link })
  } catch (e) {
    res.status(500).json({ ok:false, error: e?.message || String(e) })
  }
})

/* ===== Flutterwave verify (optional) ===== */
const hasFlwSecret = !!FLW_SECRET
async function verifyFlwAndActivate({ id, uid, tx_ref }) {
  if (!id || !uid || !tx_ref) return { ok:false, status:400, error:'Missing id, uid or tx_ref' }
  if (!hasFlwSecret)         return { ok:false, status:500, error:'Server missing FLW_SECRET' }
  if (!db)                   return { ok:false, status:500, error:'Server missing Firebase credentials' }

  const vr = await axios.get(`https://api.flutterwave.com/v3/transactions/${encodeURIComponent(id)}/verify`, {
    headers: { Authorization: `Bearer ${FLW_SECRET}` }
  })
  const d = vr?.data?.data
  if (!d) return { ok:false, status:400, error:'Invalid verify response' }

  const statusOk   = d.status === 'successful'
  const currencyOk = String(d.currency || '').toUpperCase() === 'USD'
  const txRefOk    = String(d.tx_ref || '') === String(tx_ref)
  if (!statusOk || !currencyOk || !txRefOk) {
    return { ok:false, status:400, reason:'verify_failed', got:{ status:d.status, currency:d.currency, tx_ref:d.tx_ref } }
  }

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
app.post(['/verifyFlw','/api/verifyFlw','/admin/verifyFlw'], async (req, res) => {
  try {
    const out = await verifyFlwAndActivate(req.body || {})
    if (!out.ok) return res.status(out.status || 500).json(out)
    res.json(out)
  } catch (e) {
    res.status(500).json({ ok:false, error: e?.response?.data || e?.message || String(e) })
  }
})
app.get(['/verifyFlw','/api/verifyFlw','/admin/verifyFlw'], async (req, res) => {
  try {
    const { id, uid, tx_ref } = req.query || {}
    const out = await verifyFlwAndActivate({ id, uid, tx_ref })
    if (!out.ok) return res.status(out.status || 500).json(out)
    res.json(out)
  } catch (e) {
    res.status(500).json({ ok:false, error: e?.response?.data || e?.message || String(e) })
  }
})

/* ===== Manual Pro (dev/test) ===== */
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
    if (!db) return res.status(500).json({ ok:false, error:'Server missing Firebase credentials' })
    const { idToken } = req.body || {}
    if (!idToken) return res.status(400).json({ ok:false, error:'Missing idToken' })
    const decoded = await admin.auth().verifyIdToken(String(idToken))
    const uid = decoded.uid
    if (!(await isManualProEnabled())) return res.status(403).json({ ok:false, error:'Manual Pro disabled' })
    await db.collection('users').doc(uid).set({
      pro: true,
      proSetAt: admin.firestore.FieldValue.serverTimestamp(),
      lastPayment: { provider: 'manual' }
    }, { merge: true })
    res.json({ ok:true, uid })
  } catch (e) {
    res.status(500).json({ ok:false, error: e?.response?.data || e?.message || String(e) })
  }
})

/* ===== Admin rescue endpoint ===== */
function requireAdmin(req, res) {
  if (!ADMIN_TOKEN) { res.status(500).json({ ok:false, error:'Server missing ADMIN_TOKEN' }); return false }
  const token = req.headers['x-admin-token']
  if (!token || token !== ADMIN_TOKEN) { res.status(403).json({ ok:false, error:'Forbidden (admin token)' }); return false }
  return true
}
app.post('/admin/setPro', async (req, res) => {
  try {
    if (!requireAdmin(req, res)) return
    if (!db) return res.status(500).json({ ok:false, error:'Server missing Firebase credentials' })
    const { uid, pro = true, note = 'admin setPro' } = req.body || {}
    if (!uid) return res.status(400).json({ ok:false, error:'Missing uid' })
    await db.collection('users').doc(String(uid)).set({
      pro: !!pro,
      proSetAt: admin.firestore.FieldValue.serverTimestamp(),
      lastPayment: { provider:'admin', note }
    }, { merge: true })
    res.json({ ok:true, uid:String(uid), pro:!!pro })
  } catch (e) {
    res.status(500).json({ ok:false, error: e?.response?.data || e?.message || String(e) })
  }
})

/* ===== Pesapal order & IPN ===== */
async function pesaToken() {
  if (!PESA_KEY || !PESA_SECRET) throw new Error('Missing PESA_CONSUMER_KEY/SECRET')
  try {
    const { data } = await axios.post(
      `${PESA_URL}/api/Auth/RequestToken`,
      { consumer_key: PESA_KEY, consumer_secret: PESA_SECRET },
      { headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, timeout: 15000 }
    )
    if (!data?.token) throw new Error(`No token in response: ${JSON.stringify(data)}`)
    return data.token
  } catch (e) {
    const status = e?.response?.status
    const body   = e?.response?.data
    const msg    = e?.message
    throw new Error(`RequestToken failed${status ? ` [${status}]` : ''}: ${JSON.stringify(body) || msg}`)
  }
}
app.get('/pesapal/tokenTest', async (_req, res) => {
  try {
    const token = await pesaToken()
    res.json({ ok:true, token: token ? 'RECEIVED' : 'EMPTY' })
  } catch (e) {
    res.status(500).json({ ok:false, error: e?.message || String(e) })
  }
})

app.post('/pesapal/createOrder', async (req, res) => {
  try {
    const token = await pesaToken()
    const { uid, amount = 15, currency = 'USD', email, first_name = '', last_name = '' } = req.body || {}
    if (!uid) return res.status(400).json({ ok:false, error:'Missing uid' })
    if (!PESA_IPN_ID) return res.status(500).json({ ok:false, error:'Server missing PESA_IPN_ID (register IPN first)' })

    const merchantRef = `certify_${uid}_${Date.now()}`
    const body = {
      id: merchantRef,
      currency,
      amount: Number(amount),
      description: 'Certify Pro (lifetime)',
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
    res.json({ ok: true, ...data, merchant_reference: merchantRef })
  } catch (e) {
    res.status(500).json({ ok:false, error: e?.response?.data || e?.message || String(e) })
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
    if (!orderTrackingId) return res.status(400).json({ ok:false, error:'Missing OrderTrackingId' })

    const status = await pesaFetchStatus(orderTrackingId)
    const mr = String(status?.merchant_reference || '')
    const match = mr.match(/^certify_(.+?)_/)
    const uid = match ? match[1] : null

    if (uid && status?.status_code === 1) {
      await db.collection('users').doc(uid).set({
        pro: true,
        proSetAt: admin.firestore.FieldValue.serverTimestamp(),
        lastPayment: {
          provider: 'pesapal',
          orderTrackingId,
          merchant_reference: mr,
          amount: status?.amount,
          currency: status?.currency,
          status: status?.payment_status_description
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
    return res.json({ ok:true, status })
  } catch (e) {
    const err = e?.response?.data || e?.message || String(e)
    return res.status(500).json({ ok:false, error: err })
  }
}
app.get('/pesapal/ipn', (req, res) => handlePesaNotification(req.query, res))
app.post('/pesapal/ipn', (req, res) => handlePesaNotification(req.body, res))

/* ===== Start ===== */
app.listen(PORT, () => console.log(`verify service listening on :${PORT}`))
