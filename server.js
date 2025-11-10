// server.js (ESM)
import express from 'express'
import axios from 'axios'
import admin from 'firebase-admin'
import cors from 'cors'

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

  // Pesapal
  PESA_CONSUMER_KEY,
  PESA_CONSUMER_SECRET,
  PESA_BASE = 'demo',  // 'demo' | 'live'
  PESA_IPN_ID,

} = process.env

/* ============== Small helpers ============== */
const clean = (s) => (s || '').trim().replace(/^"(.*)"$/, '$1').replace(/^'(.*)'$/, '$1')
const mask  = (s) => (s && s.length >= 8 ? s.slice(0,4)+'…'+s.slice(-4) : '(empty)')
function serverOrigin(req) {
  const xfProto = (req.headers['x-forwarded-proto'] || '').toString().split(',')[0] || 'https'
  const host = req.headers.host
  return `${xfProto}://${host}`
}

// NEW: strict, optional ISO-3166-1 alpha-2 validator (returns null if invalid)
function normalizeCountryCode(input) {
  if (!input) return null
  const cc = String(input).trim().toUpperCase()
  return /^[A-Z]{2}$/.test(cc) ? cc : null
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
// NOTE: Set PESA_CURRENCY=USD in your environment to default to USD globally.
const CURRENCY = process.env.PESA_CURRENCY || 'KES'
const AMOUNT_BY_PLAN = { pro_monthly: 19, pro_yearly: 190 }
const INTERVAL_BY_PLAN = { pro_monthly: 'month', pro_yearly: 'year' }
function amountToPlanId(amount) {
  const a = Number(amount)
  if (a === 19) return 'pro_monthly'
  if (a === 190) return 'pro_yearly'
  return null
}
function addInterval(ms, interval) {
  const d = new Date(ms)
  if (interval === 'year') d.setUTCFullYear(d.getUTCFullYear() + 1)
  else d.setUTCMonth(d.getUTCMonth() + 1)
  return d.getTime()
}

/* ============== Pesapal config ============== */
const PESA_KEY    = clean(PESA_CONSUMER_KEY)
const PESA_SECRET = clean(PESA_CONSUMER_SECRET)
const PESA_MODE   = (PESA_BASE || 'auto').toLowerCase() // 'demo' | 'live' | 'auto'
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
app.set('trust proxy', 1) // Render/Proxies

// Prepare allow list for CORS (reused on homepage for display)
const allowList = (ALLOW_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean)

const corsOptions = {
  origin(origin, cb) {
    if (!origin || allowList.includes(origin)) return cb(null, true)
    return cb(new Error('Not allowed by CORS'))
  },
  methods: ['GET','POST','OPTIONS','PUT','PATCH','DELETE'],
  allowedHeaders: ['Content-Type','Authorization','X-Admin-Token','x-admin-token'],
  credentials: true,
  optionsSuccessStatus: 204
}
app.options('*', cors(corsOptions))
app.use(cors(corsOptions))

// Body parser only when needed
app.use((req, res, next) => {
  const m = req.method
  if (m === 'POST' || m === 'PUT' || m === 'PATCH' || m === 'DELETE') {
    return express.json({ limit: '2mb' })(req, res, next)
  }
  next()
})

/* ============== Health & Debug ============== */
app.get(['/health','/api/health'], (_req, res) => {
  res.json({ ok: true, projectId: FIREBASE_PROJECT_ID || null, hasFirebaseCreds: !!hasFirebaseCreds })
})

app.get('/pesapal/health', async (req, res) => {
  try {
    const probe = String(req.query.probe || '') === '1'
    let baseResolved = null
    if (probe) {
      const { base } = await pesaToken()
      baseResolved = base
    }
    res.json({
      ok: true,
      configuredBase: PESA_MODE,
      baseResolved,
      keysPresent: !!(PESA_KEY && PESA_SECRET),
      keyPreview: mask(PESA_KEY),
      secretPreview: mask(PESA_SECRET)
    })
  } catch (e) {
    res.status(500).json({ ok:false, error: e?.response?.data || e?.message || String(e) })
  }
})

app.get('/debug/routes', (_req, res) => {
  const routes = []
  app._router.stack.forEach((m) => {
    if (m.route && m.route.path) routes.push({ methods: Object.keys(m.route.methods), path: m.route.path })
    else if (m.name === 'router' && m.handle?.stack) {
      m.handle.stack.forEach((h) => {
        if (h.route && h.route.path) routes.push({ methods: Object.keys(h.route.methods), path: h.route.path })
      })
    }
  })
  res.json({ ok:true, routes })
})

/* ============== Home page (info) ============== */
app.get('/', (req, res) => {
  const maskedSA = (FIREBASE_CLIENT_EMAIL || '').replace(/(.{3}).+(@.+)/, '$1***$2')
  const origin = serverOrigin(req)
  res.type('html').send(`
    <html><body style="font-family:system-ui;padding:16px">
      <h2>Certify Verify Service</h2>
      <ul>
        <li>Project: <code>${FIREBASE_PROJECT_ID || '—'}</code></li>
        <li>Service account: <code>${maskedSA || '—'}</code></li>
        <li>Firebase creds set: <strong style="color:${hasFirebaseCreds?'green':'crimson'}">${hasFirebaseCreds}</strong></li>
        <li>Allowed origins: ${allowList.map(o=>`<code>${o}</code>`).join(', ') || '—'}</li>
        <li>Pesapal configuredBase: <code>${PESA_MODE}</code></li>
      </ul>
      <p>Health: <a href="/health">/health</a></p>
      <p>Pesapal health: <a href="/pesapal/health?probe=1">/pesapal/health?probe=1</a></p>
      <p><strong>Register IPN:</strong> <a href="/pesapal/registerIPN">${origin}/pesapal/registerIPN</a></p>
    </body></html>
  `)
})

/* ============== Passwordless email sign-in link (optional) ============== */
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
  try {
    if (!db) return res.status(500).json({ ok:false, error:'Server missing Firebase credentials' })
    const { idToken } = req.body || {}
    if (!idToken) return res.status(400).json({ ok:false, error:'Missing idToken' })
    const decoded = await admin.auth().verifyIdToken(String(idToken))
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

/* ============== Admin rescue ============== */
function requireAdmin(req, res) {
  if (!ADMIN_TOKEN) { res.status(500).json({ ok:false, error:'Server missing ADMIN_TOKEN' }); return false }
  const token = req.headers['x-admin-token'] || req.headers['X-Admin-Token']
  if (!token || token !== ADMIN_TOKEN) { res.status(403).json({ ok:false, error:'Forbidden (admin token)' }); return false }
  return true
}
app.post('/admin/setPro', async (req, res) => {
  try {
    if (!requireAdmin(req, res)) return
    if (!db) return res.status(500).json({ ok:false, error:'Server missing Firebase credentials' })
    const { uid, pro = true, planId = 'pro_monthly', interval = 'month', note = 'admin setPro' } = req.body || {}
    if (!uid) return res.status(400).json({ ok:false, error:'Missing uid' })
    await db.collection('users').doc(String(uid)).set({
      pro: !!pro,
      planId,
      proUntil: !!pro ? addInterval(Date.now(), interval) : null,
      proSetAt: admin.firestore.FieldValue.serverTimestamp(),
      lastPayment: { provider:'admin', note }
    }, { merge: true })
    res.json({ ok:true, uid:String(uid), pro:!!pro })
  } catch (e) {
    res.status(500).json({ ok:false, error: e?.response?.data || e?.message || String(e) })
  }
})

/* ============== Pesapal: register IPN ============== */
app.get('/pesapal/registerIPN', async (req, res) => {
  try {
    const { token, url } = await pesaToken()
    const ipnUrl = `${serverOrigin(req)}/pesapal/ipn`
    const body = { url: ipnUrl, ipn_notification_type: 'GET' }
    const { data } = await axios.post(
      `${url}/api/URLSetup/RegisterIPN`,
      body,
      { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json' } }
    )
    res.json({ ok:true, data })
  } catch (e) {
    res.status(500).json({ ok:false, error: e?.response?.data || e?.message || String(e) })
  }
})

/* ============== Pesapal: token test ============== */
app.get('/pesapal/tokenTest', async (_req, res) => {
  try {
    const { base } = await pesaToken()
    res.json({ ok:true, base })
  } catch (e) {
    res.status(500).json({ ok:false, error: e?.response?.data || e?.message || String(e) })
  }
})

/* ============== Pesapal: Subscribe handler (Monthly/Yearly) ============== */
/**
 * Client POST body:
 *  { uid, planId: "pro_monthly" | "pro_yearly", email?, first_name?, last_name?, country_code? }
 * Response:
 *  { ok: true, redirect_url, order_tracking_id, merchant_reference, baseUsed }
 */
async function subscribeHandler(req, res) {
  try {
    if (!db) return res.status(500).json({ ok:false, error:'Server missing Firebase credentials' })
    const { uid, planId, email, first_name = '', last_name = '', country_code: rawCountry } = req.body || {}
    if (!uid) return res.status(400).json({ ok:false, error:'Missing uid' })
    if (!planId || !AMOUNT_BY_PLAN[planId]) return res.status(400).json({ ok:false, error:'Unknown planId' })
    if (!PESA_IPN_ID) return res.status(500).json({ ok:false, error:'Server missing PESA_IPN_ID (register IPN first)' })

    const amount = AMOUNT_BY_PLAN[planId]
    const { token, base, url } = await pesaToken()

    // Merchant reference encodes plan & uid for IPN decoding
    const merchantRef = `sub_${planId}_${uid}_${Date.now()}`

    // Optional, validated ISO-3166-1 country code (omit if invalid/unknown)
    const country_code = normalizeCountryCode(rawCountry)

    // Include cancellation_url and robust callback
    const payload = {
      id: merchantRef,
      currency: CURRENCY,
      amount: Number(amount),
      description: `Certify ${planId.replace('_',' ').toUpperCase()}`,
      callback_url: `${clean(PUBLIC_SITE_URL)}/upgrade?ref=${encodeURIComponent(merchantRef)}`,
      cancellation_url: `${clean(PUBLIC_SITE_URL)}/upgrade?cancel=1`,
      notification_id: PESA_IPN_ID,
      billing_address: {
        email_address: email || 'guest@example.com',
        first_name,
        last_name,
        ...(country_code ? { country_code } : {}) // <- only include when valid
      }
    }

    const { data } = await axios.post(
      `${url}/api/Transactions/SubmitOrderRequest`,
      payload,
      { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json' } }
    )

    // Robustly pick the redirect target across possible shapes
    const redirectUrl =
      data?.redirect_url ||
      data?.order_instructions?.redirect_url ||
      data?.payment_url ||
      null

    if (!redirectUrl) {
      return res.status(502).json({
        ok: false,
        error: 'Pesapal did not return redirect_url',
        provider_echo: {
          has_order_tracking_id: !!data?.order_tracking_id,
          keys: Object.keys(data || {})
        }
      })
    }

    // Persist order record
    await db.collection('orders').doc(merchantRef).set({
      type: 'subscription',
      planId,
      amount,
      currency: CURRENCY,
      status: 'pending',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      uid,
      provider: 'pesapal',
      orderTrackingId: data?.order_tracking_id || null,
      base
    }, { merge: true })

    // Clean response for the client
    return res.json({
      ok: true,
      baseUsed: base,
      redirect_url: redirectUrl,
      order_tracking_id: data?.order_tracking_id,
      merchant_reference: merchantRef
    })
  } catch (e) {
    return res.status(500).json({ ok:false, error: e?.response?.data || e?.message || String(e) })
  }
}

// Register BOTH routes (alias keeps your existing frontend path working)
app.post('/api/pesapal/subscribe', subscribeHandler)
app.post('/pesapal/createOrder',   subscribeHandler)

/* ============== Pesapal: manual status check (optional) ============== */
app.get('/pesapal/getStatus', async (req, res) => {
  try {
    const orderTrackingId = req.query.orderTrackingId
    if (!orderTrackingId) return res.status(400).json({ ok:false, error:'Missing orderTrackingId' })
    const { token, url } = await pesaToken()
    const { data } = await axios.get(
      `${url}/api/Transactions/GetTransactionStatus?orderTrackingId=${encodeURIComponent(orderTrackingId)}`,
      { headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' } }
    )
    res.json({ ok:true, status: data })
  } catch (e) {
    res.status(500).json({ ok:false, error: e?.response?.data || e?.message || String(e) })
  }
})

/* ============== Pesapal: IPN (GET/POST) ============== */
async function handlePesaNotification(params, res) {
  try {
    const orderTrackingId = params?.OrderTrackingId || params?.orderTrackingId
    if (!orderTrackingId) return res.status(400).json({ ok:false, error:'Missing OrderTrackingId' })

    const { token, url } = await pesaToken()
    const { data: status } = await axios.get(
      `${url}/api/Transactions/GetTransactionStatus?orderTrackingId=${encodeURIComponent(orderTrackingId)}`,
      { headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' } }
    )

    const mr = String(status?.merchant_reference || '')
    const match = mr.match(/^sub_([^_]+)_(.+?)_\d+$/)
    const planId = match ? match[1] : null
    const uid    = match ? match[2] : null

    const paid = Number(status?.status_code) === 1
    const amount = status?.amount
    const currency = String(status?.currency || CURRENCY).toUpperCase()

    if (paid && db && uid) {
      const finalPlanId = planId || amountToPlanId(amount) || 'pro_monthly'
      const interval = INTERVAL_BY_PLAN[finalPlanId] || 'month'
      const now = Date.now()
      const proUntil = addInterval(now, interval)

      await db.collection('users').doc(uid).set({
        pro: true,
        planId: finalPlanId,
        proUntil,
        proSetAt: admin.firestore.FieldValue.serverTimestamp(),
        lastPayment: {
          provider: 'pesapal',
          orderTrackingId,
          merchant_reference: mr,
          amount,
          currency,
          status: status?.payment_status_description
        }
      }, { merge: true })

      await db.collection('orders').doc(mr).set({
        status: 'paid',
        paidAt: admin.firestore.FieldValue.serverTimestamp(),
        statusPayload: status
      }, { merge: true })
    } else {
      await db?.collection('orders').doc(mr || orderTrackingId).set({
        status: 'failed',
        statusPayload: status
      }, { merge: true }).catch(()=>{})
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

/* ============== Start ============== */
app.listen(PORT, () => {
  console.log(`verify service listening on :${PORT}`)
  console.log(`Allowed origins: ${allowList.join(', ') || '(none)'}`)
})
