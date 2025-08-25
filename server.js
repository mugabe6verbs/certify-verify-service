import express from 'express'
import axios from 'axios'
import admin from 'firebase-admin'
import cors from 'cors'

const {
  PORT = 8080,
  FLW_SECRET,
  FIREBASE_PROJECT_ID,
  FIREBASE_CLIENT_EMAIL,
  FIREBASE_PRIVATE_KEY,
  ALLOW_ORIGINS = 'http://localhost:5173',
  PUBLIC_SITE_URL = 'https://certificate-generator-345be.web.app',
  // NEW: env override to allow manual pro without Firestore flag (for testing)
  ALLOW_MANUAL_PRO
} = process.env

// --- Env checks
const hasFlwSecret = !!FLW_SECRET
const privateKeyRaw = FIREBASE_PRIVATE_KEY || ''
const privateKey = privateKeyRaw.replace(/\\n/g, '\n')
const hasFirebaseCreds = !!(FIREBASE_PROJECT_ID && FIREBASE_CLIENT_EMAIL && privateKeyRaw)
const allowList = ALLOW_ORIGINS.split(',').map(s => s.trim()).filter(Boolean)
const ALLOW_MANUAL_PRO_ENV = String(ALLOW_MANUAL_PRO || '').toLowerCase() === 'true'

// --- Firebase Admin
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

// --- Health BEFORE any CORS gate (always reachable)
app.get('/health', (_req, res) => {
  res.json({ ok: true, hasFlwSecret, hasFirebaseCreds, allowList, projectId: FIREBASE_PROJECT_ID || null })
})

// --- CORS (tolerant: allow no Origin; allow only allowList when Origin present)
const corsOptions = {
  origin(origin, cb) {
    if (!origin || allowList.includes(origin)) return cb(null, true)
    return cb(new Error('Not allowed by CORS'))
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 204
}
app.options('*', cors(corsOptions))
app.use(cors(corsOptions))

// --- Home
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
        <li>Allowed origins: ${allowList.map(o=>`<code>${o}</code>`).join(', ') || '—'}</li>
        <li>ALLOW_MANUAL_PRO (env): <code>${String(ALLOW_MANUAL_PRO_ENV)}</code></li>
      </ul>
      <p>Health: <a href="/health">/health</a></p>
      <p>Verify endpoint: <code>POST /verifyFlw</code></p>
      <p>Debug flags: <a href="/debugFlags">/debugFlags</a></p>
    </body></html>
  `)
})

// --- Helper: is manual pro enabled? (env override OR Firestore flag)
async function isManualProEnabled() {
  if (ALLOW_MANUAL_PRO_ENV) return true
  if (!db) return false
  try {
    const snap = await db.collection('config').doc('flags').get()
    return !!(snap.exists && snap.get('allowManualPro') === true)
  } catch {
    return false
  }
}

// --- Debug: see what the server reads
app.get('/debugFlags', async (_req, res) => {
  try {
    let snap = null
    let exists = false
    let allowManualProField = null
    if (db) {
      snap = await db.collection('config').doc('flags').get()
      exists = !!(snap && snap.exists)
      allowManualProField = exists ? snap.get('allowManualPro') : null
    }
    res.json({
      ok: true,
      projectId: FIREBASE_PROJECT_ID || null,
      envAllowManualPro: ALLOW_MANUAL_PRO_ENV,
      flagsDocExists: exists,
      allowManualProField
    })
  } catch (e) {
    res.status(500).json({ ok:false, error: e?.message || String(e) })
  }
})

// --- Shared verify → activates Pro on success
async function verifyFlwAndActivate({ id, uid, tx_ref }) {
  if (!id || !uid || !tx_ref) return { ok: false, status: 400, error: 'Missing id, uid or tx_ref' }
  if (!hasFlwSecret) return { ok: false, status: 500, error: 'Server missing FLW_SECRET' }
  if (!db) return { ok: false, status: 500, error: 'Server missing Firebase credentials' }

  const vr = await axios.get(`https://api.flutterwave.com/v3/transactions/${encodeURIComponent(id)}/verify`, {
    headers: { Authorization: `Bearer ${FLW_SECRET}` }
  })
  const d = vr?.data?.data
  if (!d) return { ok: false, status: 400, error: 'Invalid verify response' }

  const statusOk   = d.status === 'successful'
  const currencyOk = String(d.currency || '').toUpperCase() === 'USD'
  const txRefOk    = String(d.tx_ref || '') === String(tx_ref)

  if (!statusOk || !currencyOk || !txRefOk) {
    return {
      ok: false,
      status: 400,
      reason: 'verify_failed',
      got: { status: d.status, currency: d.currency, tx_ref: d.tx_ref }
    }
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

  return { ok: true, uid, tx_ref, amount: d.amount, currency: d.currency }
}

// --- Verify (POST)
app.post('/verifyFlw', async (req, res) => {
  try {
    const out = await verifyFlwAndActivate(req.body || {})
    if (!out.ok) return res.status(out.status || 500).json(out)
    res.json(out)
  } catch (e) {
    const err = e?.response?.data || e?.message || String(e)
    res.status(500).json({ ok:false, error: err })
  }
})

// --- Verify (GET) — debug fallback (id, uid, tx_ref as query)
app.get('/verifyFlw', async (req, res) => {
  try {
    const { id, uid, tx_ref } = req.query || {}
    const out = await verifyFlwAndActivate({ id, uid, tx_ref })
    if (!out.ok) return res.status(out.status || 500).json(out)
    res.json(out)
  } catch (e) {
    const err = e?.response?.data || e?.message || String(e)
    res.status(500).json({ ok:false, error: err })
  }
})

// --- Manual Pro (dev/test only; allows env override or Firestore flag)
app.post('/manualPro', async (req, res) => {
  try {
    if (!db) return res.status(500).json({ ok:false, error:'Server missing Firebase credentials' })
    const { idToken } = req.body || {}
    if (!idToken) return res.status(400).json({ ok:false, error:'Missing idToken' })

    const decoded = await admin.auth().verifyIdToken(String(idToken))
    const uid = decoded.uid

    const enabled = await isManualProEnabled()
    if (!enabled) {
      return res.status(403).json({ ok:false, error:'Manual Pro disabled', project: FIREBASE_PROJECT_ID })
    }

    await db.collection('users').doc(uid).set({
      pro: true,
      proSetAt: admin.firestore.FieldValue.serverTimestamp(),
      lastPayment: {
        provider: ALLOW_MANUAL_PRO_ENV ? 'manual-env' : 'manual',
        note: ALLOW_MANUAL_PRO_ENV
          ? 'Activated via /manualPro with ALLOW_MANUAL_PRO=true'
          : 'Activated via /manualPro while allowManualPro=true'
      }
    }, { merge: true })

    res.json({ ok:true, uid })
  } catch (e) {
    const err = e?.response?.data || e?.message || String(e)
    res.status(500).json({ ok:false, error: err })
  }
})

// --- Generate email link (fallback when Firebase email quota is hit)
app.post('/makeEmailLink', async (req, res) => {
  try {
    if (!db) return res.status(500).json({ ok:false, error:'Server missing Firebase credentials' })
    const { email } = req.body || {}
    if (!email) return res.status(400).json({ ok:false, error:'Missing email' })

    const actionCodeSettings = { url: `${PUBLIC_SITE_URL}/finish-signin`, handleCodeInApp: true }
    const link = await admin.auth().generateSignInWithEmailLink(String(email), actionCodeSettings)
    return res.json({ ok:true, link })
  } catch (e) {
    const err = e?.message || String(e)
    return res.status(500).json({ ok:false, error: err })
  }
})

app.listen(PORT, () => console.log(`verify service listening on :${PORT}`))
