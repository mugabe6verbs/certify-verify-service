import express from 'express'
import cors from 'cors'
import axios from 'axios'
import admin from 'firebase-admin'

const {
  PORT = 8080,
  FLW_SECRET,
  FIREBASE_PROJECT_ID,
  FIREBASE_CLIENT_EMAIL,
  FIREBASE_PRIVATE_KEY,
  ALLOW_ORIGINS = 'http://localhost:5173'
} = process.env

const hasFlwSecret = !!FLW_SECRET
const privateKeyRaw = (FIREBASE_PRIVATE_KEY || '')
const privateKey = privateKeyRaw.replace(/\\n/g, '\n')
const hasFirebaseCreds = !!(FIREBASE_PROJECT_ID && FIREBASE_CLIENT_EMAIL && privateKeyRaw)

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
    console.warn('⚠ Firebase credentials not set yet — Firestore writes disabled until you add them.')
  }
} catch (e) {
  console.warn('⚠ Firebase Admin init warning:', e?.message || e)
}

const app = express()
app.use(express.json())

const allowList = ALLOW_ORIGINS.split(',').map(s => s.trim()).filter(Boolean)
app.use(cors({
  origin(origin, cb){
    if (!origin || allowList.includes(origin)) return cb(null, true)
    return cb(new Error('Not allowed by CORS'))
  }
}))

app.get('/', (_req, res) => {
  res.type('html').send(`
    <html><body style="font-family:system-ui;padding:16px">
      <h2>Certify Verify Service</h2>
      <ul>
        <li>FLW_SECRET set: <strong style="color:${hasFlwSecret?'green':'crimson'}">${hasFlwSecret}</strong></li>
        <li>Firebase creds set: <strong style="color:${hasFirebaseCreds?'green':'crimson'}">${hasFirebaseCreds}</strong></li>
        <li>Allowed origins: ${allowList.map(o=>`<code>${o}</code>`).join(', ') || '—'}</li>
      </ul>
      <p>Health: <a href="/health">/health</a></p>
      <p>Verify endpoint: <code>POST /verifyFlw</code></p>
    </body></html>
  `)
})

app.get('/health', (_req, res) => {
  res.json({ ok: true, hasFlwSecret, hasFirebaseCreds, allowList })
})

app.post('/verifyFlw', async (req, res) => {
  try{
    const { id, uid, tx_ref } = req.body || {}
    if (!id || !uid || !tx_ref) return res.status(400).json({ ok:false, error:'Missing id, uid or tx_ref' })
    if (!hasFlwSecret) return res.status(500).json({ ok:false, error:'Server missing FLW_SECRET' })
    if (!db) return res.status(500).json({ ok:false, error:'Server missing Firebase credentials' })

    const vr = await axios.get(`https://api.flutterwave.com/v3/transactions/${encodeURIComponent(id)}/verify`, {
      headers: { Authorization: `Bearer ${FLW_SECRET}` }
    })
    const d = vr?.data?.data
    if (!d) return res.status(400).json({ ok:false, error:'Invalid verify response' })

    const statusOk   = d.status === 'successful'
    const currencyOk = String(d.currency || '').toUpperCase() === 'USD'
    const txRefOk    = String(d.tx_ref || '') === String(tx_ref)

    if (!statusOk || !currencyOk || !txRefOk){
      return res.status(400).json({
        ok:false, reason:'verify_failed',
        got:{ status:d.status, currency:d.currency, tx_ref:d.tx_ref }
      })
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

    res.json({ ok:true, uid, tx_ref, amount:d.amount, currency:d.currency })
  }catch(e){
    const err = e?.response?.data || e?.message || String(e)
    res.status(500).json({ ok:false, error: err })
  }
})
// POST /manualPro  — dev/test only (respects config/flags.allowManualPro)
app.post('/manualPro', async (req, res) => {
  try {
    if (!db) return res.status(500).json({ ok:false, error:'Server missing Firebase credentials' })

    // 1) Require an ID token from the signed-in client
    const { idToken } = req.body || {}
    if (!idToken) return res.status(400).json({ ok:false, error:'Missing idToken' })

    // 2) Verify token → get caller's uid
    const decoded = await admin.auth().verifyIdToken(String(idToken))
    const uid = decoded.uid

    // 3) Check your feature flag in Firestore
    const flagsSnap = await db.collection('config').doc('flags').get()
    const flags = flagsSnap.exists ? flagsSnap.data() : {}
    if (!flags.allowManualPro) {
      return res.status(403).json({ ok:false, error:'Manual Pro disabled' })
    }

    // 4) Set Pro
    await db.collection('users').doc(uid).set({
      pro: true,
      proSetAt: admin.firestore.FieldValue.serverTimestamp(),
      lastPayment: {
        provider: 'manual',
        note: 'Activated via /manualPro while allowManualPro=true'
      }
    }, { merge: true })

    res.json({ ok:true, uid })
  } catch (e) {
    const err = e?.response?.data || e?.message || String(e)
    res.status(500).json({ ok:false, error: err })
  }
})

app.listen(PORT, () => console.log(`verify service listening on :${PORT}`))

