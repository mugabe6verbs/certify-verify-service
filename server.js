import express from 'express'
import cors from 'cors'
import axios from 'axios'
import admin from 'firebase-admin'

const {
  PORT = 8080,
  FLW_SECRET,               // Flutterwave secret key (test/live) - use any placeholder for now
  FIREBASE_PROJECT_ID,
  FIREBASE_CLIENT_EMAIL,
  FIREBASE_PRIVATE_KEY,     // paste with \n escaped
  ALLOW_ORIGINS = 'http://localhost:5173'
} = process.env

if (!FLW_SECRET) console.warn('⚠ FLW_SECRET not set. The /verifyFlw endpoint will fail until you add it.')

const privateKey = (FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n')
if (!FIREBASE_PROJECT_ID || !FIREBASE_CLIENT_EMAIL || !privateKey) {
  console.warn('⚠ Firebase service account env vars not set. Writes to Firestore will fail until you add them.')
}
try {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: FIREBASE_PROJECT_ID,
      clientEmail: FIREBASE_CLIENT_EMAIL,
      privateKey
    })
  })
} catch (e) {
  console.warn('Firebase admin init warning:', e?.message || e)
}
const db = admin.firestore?.()

const app = express()
app.use(express.json())

const allowList = ALLOW_ORIGINS.split(',').map(s => s.trim()).filter(Boolean)
app.use(cors({
  origin(origin, cb){
    if (!origin || allowList.includes(origin)) return cb(null, true)
    return cb(new Error('Not allowed by CORS'))
  }
}))

app.get('/', (_,res)=> res.send('OK'))

// POST /verifyFlw { id, uid, tx_ref }
app.post('/verifyFlw', async (req, res) => {
  try{
    const { id, uid, tx_ref } = req.body || {}
    if (!id || !uid || !tx_ref) return res.status(400).json({ ok:false, error:'Missing id, uid or tx_ref' })
    if (!FLW_SECRET) return res.status(500).json({ ok:false, error:'Server missing FLW_SECRET' })
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
      return res.status(400).json({ ok:false, reason:'verify_failed', got:{ status:d.status, currency:d.currency, tx_ref:d.tx_ref } })
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

app.listen(PORT, ()=> console.log(`verify service listening on :${PORT}`))
