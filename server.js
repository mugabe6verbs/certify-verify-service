// server.js
import express from 'express'
import axios from 'axios'
import admin from 'firebase-admin'
import cors from 'cors'

const {
  PORT = 8080,
  // Flutterwave (kept; optional)
  FLW_SECRET,

  // Firebase Admin
  FIREBASE_PROJECT_ID,
  FIREBASE_CLIENT_EMAIL,
  FIREBASE_PRIVATE_KEY,

  // CORS + site
  ALLOW_ORIGINS = 'http://localhost:5173,https://certificate-generator-345be.web.app,https://certificate-generator-345be.firebaseapp.com',
  PUBLIC_SITE_URL = 'https://certificate-generator-345be.web.app',

  // Feature flags
  ALLOW_MANUAL_PRO,
  ADMIN_TOKEN,

  // Pesapal (NEW)
  PESA_CONSUMER_KEY,
  PESA_CONSUMER_SECRET,
  PESA_BASE = 'demo',        // 'demo' or 'live'
  PESA_IPN_ID                // set after /pesapal/registerIPN (one-time)
} = process.env

// ---- Env & Admin
const hasFlwSecret = !!FLW_SECRET
const pkRaw = FIREBASE_PRIVATE_KEY || ''
const privateKey = pkRaw.replace(/\\n/g, '\n')
const hasFirebaseCreds = !!(FIREBASE_PROJECT_ID && FIREBASE_CLIENT_EMAIL && pkRaw)
const allowList = ALLOW_ORIGINS.split(',').map(s=>s.trim()).filter(Boolean)
const ALLOW_MANUAL_PRO_ENV = String(ALLOW_MANUAL_PRO || '').toLowerCase() === 'true'

// Firebase Admin init
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
    console.warn('⚠ Firebase credentials not set — Firestore writes disabled until you add them.')
  }
} catch (e) {
  console.warn('⚠ Firebase Admin init warning:', e?.message || e)
}

const app = express()
app.use(express.json())

// ---- CORS (allow no-origin; restrict when Origin present)
const corsOptions = {
  origin(origin, cb) {
    if (!origin || allowList.includes(origin)) return cb(null, true)
    return cb(new Error('Not allowed by CORS'))
  },
  methods: ['GET','POST','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','X-Admin-Token','x-admin-token'],
  optionsSuccessStatus: 204
}
app.options('*', cors(corsOptions))
app.use(cors(corsOptions))

// ---- Health (aliases)
app.get(['/health','/api/health'], (_req, res) => {
  res.json({ ok:true, projectId: FIREBASE_PROJECT_ID || null, hasFlwSecret, hasFirebaseCreds, allowList })
})

// ---- Home
app.get('/', (_req, res) => {
  const maskedSA = (FIREBASE_CLIENT_EMAIL || '').replace(/(.{3}).+(@.+)/, '$1***$2')
  res.type('html').send(`
    <html><body style="font-family:system-ui;padding:16px">
      <h2>Certify Verify Service</h2>
      <ul>
        <li>Project: <code>${FIREBASE_PROJECT_ID || '—'}</code></li>
        <li>Service account: <code>${maskedSA || '—'}</code></li>
        <li>FLW_SECRET set: <strong style="color:${hasFlwSecret?'green':'crimson'}">${hasFlwSecret}</strong></li>
        <li>Firebase creds set: <strong style="color:${hasFirebaseCreds?'green':'crimson'}">${hasFirebaseCreds}</strong></li>
        <li>Allowed origins: ${allowList.map(o=>`<code>${o}</code>`).join(', ')}</li>
        <li>ALLOW_MANUAL_PRO: <code>${String(ALLOW_MANUAL_PRO_ENV)}</code></li>
      </ul>
      <p>Health: <a href="/health">/health</a></p>
      <p>Verify endpoint: <code>POST /verifyFlw</code></p>
      <p>Email link endpoint: <code>POST /makeEmailLink</code></p>
      <p>Pesapal health: <a href="/pesapal/health">/pesapal/health</a></p>
    </body></html>
  `)
})

// ---------------------------------------------------------------------------
// Flutterwave verify (kept)
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Email link (kept)
// ---------------------------------------------------------------------------
app.post(['/makeEmailLink','/api/makeEmailLink','/admin/makeEmailLink'], async (req, res) => {
  try {
    if (!db) return res.status(500).json({ ok:false, error:'Server missing Firebase credentials' })
    const { email } = req.body || {}
    if (!email) return res.status(400).json({ ok:false, error:'Missing email' })
    const actionCodeSettings = { url: `${PUBLIC_SITE_URL}/finish-signin`, handleCodeInApp: true }
    const link = await admin.auth().generateSignInWithEmailLink(String(email), actionCodeSettings)
    res.json({ ok:true, link })
  } catch (e) {
    res.status(500).json({ ok:false, error: e?.message || String(e) })
  }
})

// ---------------------------------------------------------------------------
// Manual Pro (kept)
// ---------------------------------------------------------------------------
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
      lastPayment: { provider: ALLOW_MANUAL_PRO_ENV ? 'manual-env' : 'manual' }
    }, { merge: true })
    res.json({ ok:true, uid })
  } catch (e) {
    res.status(500).json({ ok:false, error: e?.response?.data || e?.message || String(e) })
  }
})

// Admin rescue
function requireAdmin(req, res) {
  if (!ADMIN_TOKEN) {
    res.status(500).json({ ok:false, error:'Server missing ADMIN_TOKEN' })
    return false
  }
  const token = req.headers['x-admin-token']
  if (!token || token !== ADMIN_TOKEN) {
    res.status(403).json({ ok:false, error:'Forbidden (admin token)' })
    return false
  }
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

// ---------------------------------------------------------------------------
// Pesapal (NEW)
// ---------------------------------------------------------------------------
const PESA_KEY    = PESA_CONSUMER_KEY || ''
const PESA_SECRET = PESA_CONSUMER_SECRET || ''
const PESA_MODE   = (PESA_BASE || 'demo').toLowerCase() // 'demo' | 'live'
const PESA_DEMO   = 'https://cybqa.pesapal.com/pesapalv3'
const PESA_LIVE   = 'https://pay.pesapal.com/v3'
const PESA_URL    = PESA_MODE === 'live' ? PESA_LIVE : PESA_DEMO

async function pesaToken() {
  if (!PESA_KEY || !PESA_SECRET) throw new Error('Missing PESA_CONSUMER_KEY/SECRET')
  const { data } = await axios.post(
    `${PESA_URL}/api/Auth/RequestToken`,
    { consumer_key: PESA_KEY, consumer_secret: PESA_SECRET },
    { headers: { 'Content-Type': 'application/json', Accept: 'application/json' } }
  )
  if (!data?.token) throw new Error('Failed to get Pesapal token')
  return data.token
}

// health
app.get('/pesapal/health', (_req, res) => {
  res.json({
    ok: true,
    base: PESA_MODE,
    hasKeys: !!(PESA_KEY && PESA_SECRET),
    hasIpn: !!PESA_IPN_ID
  })
})

// one-time: register IPN -> returns ipn_id; set env PESA_IPN_ID and redeploy
app.post('/pesapal/registerIPN', async (req, res) => {
  try {
    const token = await pesaToken()
    const publicSite = (PUBLIC_SITE_URL || '').replace(/\/$/, '')
    const ipnUrl = req.body?.url || `${publicSite}/pesapal/ipn`
    const { data } = await axios.post(
      `${PESA_URL}/api/URLSetup/RegisterIPN`,
      { url: ipnUrl, ipn_notification_type: 'GET' },
      { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json' } }
    )
    res.json({ ok: true, ...data }) // data.ipn_id
  } catch (e) {
    res.status(500).json({ ok:false, error: e?.response?.data || e?.message || String(e) })
  }
})

// create order -> redirect_url for checkout
app.post('/pesapal/createOrder', async (req, res) => {
  try {
    const token = await pesaToken()
    const { uid, amount = 15, currency = 'USD', email, first_name = '', last_name = '' } = req.body || {}
    if (!uid) return res.status(400).json({ ok:false, error:'Missing uid' })
    if (!PESA_IPN_ID) return res.status(500).json({ ok:false, error:'Server missing PESA_IPN_ID (register IPN first)' })

    const publicSite = (PUBLIC_SITE_URL || '').replace(/\/$/, '')
    const merchantRef = `certify_${uid}_${Date.now()}`
    const body = {
      id: merchantRef,
      currency,
      amount: Number(amount),
      description: 'Certify Pro (lifetime)',
      callback_url: `${publicSite}/upgrade`,
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
    // { order_tracking_id, redirect_url, merchant_reference }
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

    // COMPLETED => flip Pro
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

    // IPN: must respond with ack JSON
    if (params?.OrderNotificationType === 'IPNCHANGE') {
      return res.json({
        orderNotificationType: 'IPNCHANGE',
        orderTrackingId,
        orderMerchantReference: status?.merchant_reference || '',
        status: 200
      })
    }
    // Non-IPN (browser call / debug)
    return res.json({ ok:true, status })
  } catch (e) {
    const err = e?.response?.data || e?.message || String(e)
    return res.status(500).json({ ok:false, error: err })
  }
}

app.get('/pesapal/ipn', (req, res) => handlePesaNotification(req.query, res))
app.post('/pesapal/ipn', (req, res) => handlePesaNotification(req.body, res))

// ---------------------------------------------------------------------------

app.listen(PORT, () => console.log(`verify service listening on :${PORT}`))
