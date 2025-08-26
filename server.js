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
  ALLOW_ORIGINS = 'http://localhost:5173,https://certificate-generator-345be.web.app,https://certificate-generator-345be.firebaseapp.com',
  PUBLIC_SITE_URL = 'https://certificate-generator-345be.web.app',
  ALLOW_MANUAL_PRO,
  ADMIN_TOKEN,
} = process.env

// ---- Env & Admin
const hasFlwSecret = !!FLW_SECRET
const pkRaw = FIREBASE_PRIVATE_KEY || ''
const privateKey = pkRaw.replace(/\\n/g, '\n')
const hasFirebaseCreds = !!(FIREBASE_PROJECT_ID && FIREBASE_CLIENT_EMAIL && pkRaw)
const allowList = ALLOW_ORIGINS.split(',').map(s=>s.trim()).filter(Boolean)
const ALLOW_MANUAL_PRO_ENV = String(ALLOW_MANUAL_PRO || '').toLowerCase() === 'true'

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
    </body></html>
  `)
})

// ---- Helpers
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

async function isManualProEnabled() {
  if (ALLOW_MANUAL_PRO_ENV) return true
  if (!db) return false
  try {
    const snap = await db.collection('config').doc('flags').get()
    return !!(snap.exists && snap.get('allowManualPro') === true)
  } catch { return false }
}

// ---- Verify (POST/GET) with aliases
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

// ---- Email link (POST) with aliases  <<< THIS FIXES YOUR 404
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

// ---- Manual Pro (dev/test)
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

// ---- Admin override (rescue)
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

app.listen(PORT, () => console.log(`verify service listening on :${PORT}`))
