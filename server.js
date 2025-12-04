import express from 'express'
import axios from 'axios'
import admin from 'firebase-admin'
import cors from 'cors'
import dns from 'dns/promises'
import helmet from 'helmet'
import compression from 'compression'
import rateLimit from 'express-rate-limit'
import path from 'path'
import { fileURLToPath } from 'url'
import crypto from 'crypto'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

/* ============== ENV & helpers ============== */
const {
  PORT = 8080,
  FIREBASE_PROJECT_ID,
  FIREBASE_CLIENT_EMAIL,
  FIREBASE_PRIVATE_KEY,
  ALLOW_ORIGINS = 'http://localhost:5173,https://certificate-generator-345be.web.app,https://certificate-generator-345be.firebaseapp.com,https://certify-verify-service-2.onrender.com',
  ADMIN_TOKEN,
  ADMIN_PASSWORD,
  PESA_CONSUMER_KEY,
  PESA_CONSUMER_SECRET,
  PESA_BASE = 'demo',
  PESA_IPN_ID,
  VERIFY_CNAME_TARGET = 'custom.certifyhq.com',
  PUBLIC_SITE_URL = 'https://certificate-generator-345be.web.app',
  ALLOW_MANUAL_PRO
} = process.env

const clean = (s) => (s || '').trim().replace(/^"(.*)"$/, '$1').replace(/^'(.*)'$/, '$1')
const mask = (s) => (s && s.length >= 8 ? s.slice(0, 4) + '…' + s.slice(-4) : '(empty)')

function serverOrigin(req) {
  const xfProto = (req.headers['x-forwarded-proto'] || '').toString().split(',')[0] || 'https'
  return `${xfProto}://${req.headers.host}`
}

function normalizeCountryCode(input) {
  if (!input) return null
  const cc = String(input).trim().toUpperCase()
  return /^[A-Z]{2}$/.test(cc) ? cc : null
}

function addInterval(ms, interval) {
  const d = new Date(ms)
  if (interval === 'year') d.setUTCFullYear(d.getUTCFullYear() + 1)
  else d.setUTCMonth(d.getUTCMonth() + 1)
  return d.getTime()
}

const AMOUNT_BY_PLAN = { pro_monthly: 19, pro_yearly: 190 }
const INTERVAL_BY_PLAN = { pro_monthly: 'month', pro_yearly: 'year' }
function amountToPlanId(amount) {
  const a = Number(amount)
  if (a === 19) return 'pro_monthly'
  if (a === 190) return 'pro_yearly'
  return null
}

/* ============== Firebase Admin ============== */
const privateKey = clean(FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n')
let db = null
if (FIREBASE_PROJECT_ID && FIREBASE_CLIENT_EMAIL && privateKey) {
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

const ALLOW_MANUAL_PRO_ENV = String(ALLOW_MANUAL_PRO || '').toLowerCase() === 'true'

/* ============== Pesapal helpers ============== */
const PESA_KEY = clean(PESA_CONSUMER_KEY)
const PESA_SECRET = clean(PESA_CONSUMER_SECRET)
const PESA_MODE = (PESA_BASE || 'auto').toLowerCase()
const PESA_URLS = { demo: 'https://cybqa.pesapal.com/pesapalv3', live: 'https://pay.pesapal.com/v3' }

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
  const order = preferred === 'auto' ? ['demo', 'live'] : [preferred, preferred === 'demo' ? 'live' : 'demo']
  let lastErr = null
  for (const b of order) {
    try { return await tokenFor(b) } 
    catch (e) { if (isInvalidKeyErr(e)) { lastErr = e; continue } else { throw e } }
  }
  throw lastErr
}

/* ============== Express setup ============== */
const app = express()
app.set('trust proxy', 1)

// Middleware
app.use(express.json({ limit: '2mb' }))
const allowList = (ALLOW_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean)
app.use(cors({
  origin(origin, cb) {
    if (!origin || allowList.includes(origin)) return cb(null, true)
    return cb(new Error('Not allowed by CORS'))
  },
  methods: ['GET','POST','OPTIONS','PUT','PATCH','DELETE'],
  allowedHeaders: ['Content-Type','Authorization','X-Admin-Token','x-admin-token'],
  credentials: true
}))
app.use(helmet())
app.use(compression())

/* ============== Rate limiters ============== */
const globalLimiter = rateLimit({ windowMs: 60 * 1000, max: 500, standardHeaders: true, legacyHeaders: false })
const adminVerifyLimiter = rateLimit({ windowMs: 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false })
const pesapalLimiter = rateLimit({ windowMs: 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false })
const ipnLimiter = rateLimit({ windowMs: 60 * 1000, max: 300, standardHeaders: true, legacyHeaders: false })
const orgVerifyLimiter = rateLimit({ windowMs: 60*1000, max:5, message:{ok:false,error:'Too many verification attempts'}, standardHeaders:true, legacyHeaders:false })
app.use(globalLimiter)

/* ============== Auth helpers ============== */
async function authenticate(req,res,next){
  try{
    const authHeader = req.headers.authorization || ''
    if(!authHeader.startsWith('Bearer ')) return res.status(401).json({ok:false,error:'Missing Bearer token'})
    const idToken = authHeader.split('Bearer ')[1]
    req.user = await admin.auth().verifyIdToken(String(idToken), true)
    next()
  } catch {
    res.status(401).json({ok:false,error:'Invalid auth token'})
  }
}

function requireAdmin(req,res){
  const token = req.headers['x-admin-token'] || req.headers['X-Admin-Token']
  if(!token || token !== ADMIN_TOKEN){ res.status(403).json({ok:false,error:'Forbidden (admin token)'}); return false }
  return true
}

/* ============== Health check ============== */
app.get(['/health','/api/health'], (_req,res)=>res.json({ok:true,projectId:FIREBASE_PROJECT_ID||null}))

/* ============== Passwordless Email Sign-in ============== */
app.post(['/makeEmailLink','/api/makeEmailLink','/admin/makeEmailLink'], async (req,res)=>{
  try{
    if(!db) return res.status(500).json({ok:false,error:'Firebase creds missing'})
    const { email } = req.body||{}
    if(!email) return res.status(400).json({ok:false,error:'Missing email'})
    const link = await admin.auth().generateSignInWithEmailLink(String(email), {url:`${clean(PUBLIC_SITE_URL)}/finish-signin`, handleCodeInApp:true})
    res.json({ok:true,link})
  }catch(e){ res.status(500).json({ok:false,error:e?.message||String(e)}) }
})

/* ============== Manual Pro ============== */
async function isManualProEnabled(){ return ALLOW_MANUAL_PRO_ENV || (db && ((await db.collection('config').doc('flags').get()).get('allowManualPro')===true)) }
app.post(['/manualPro','/api/manualPro','/admin/manualPro'], async (req,res)=>{
  try{
    if(!db) return res.status(500).json({ok:false,error:'Firebase creds missing'})
    const { idToken } = req.body||{}
    if(!idToken) return res.status(400).json({ok:false,error:'Missing idToken'})
    const decoded = await admin.auth().verifyIdToken(String(idToken))
    const uid = decoded.uid
    if(!(await isManualProEnabled())) return res.status(403).json({ok:false,error:'Manual Pro disabled'})
    await db.collection('users').doc(uid).set({
      pro:true,
      planId:'pro_monthly',
      proUntil:addInterval(Date.now(),'month'),
      proSetAt:admin.firestore.FieldValue.serverTimestamp(),
      lastPayment:{provider:'manual'}
    },{merge:true})
    res.json({ok:true,uid})
  }catch(e){ res.status(500).json({ok:false,error:e?.response?.data||e?.message||String(e)}) }
})

/* ============== Admin verify ============== */
app.post('/api/admin/verify', adminVerifyLimiter, async (req,res)=>{
  try{
    const { idToken,password } = req.body||{}
    if(!idToken||!password) return res.status(400).json({ok:false,error:'Missing idToken or password'})
    let decoded
    try{ decoded = await admin.auth().verifyIdToken(String(idToken)) } catch { return res.status(401).json({ok:false,error:'Invalid idToken'}) }
    if(!ADMIN_PASSWORD) return res.status(500).json({ok:false,error:'Admin password not configured'})
    const safeEqual = (a='',b='')=>{
      const ab=Buffer.from(String(a)),bb=Buffer.from(String(b))
      return ab.length===bb.length && crypto.timingSafeEqual(ab,bb)
    }
    if(!safeEqual(password,ADMIN_PASSWORD)) return res.status(403).json({ok:false,error:'Invalid password'})
    await admin.auth().setCustomUserClaims(decoded.uid,{admin:true})
    res.json({ok:true,message:'Verified; refresh token to pick up admin claim'})
  }catch(e){ console.error('admin/verify error',e); res.status(500).json({ok:false,error:e?.message||String(e)}) }
})

/* ============== Org domain verification ============== */
app.get('/api/org/:orgId/verify-domain', authenticate, orgVerifyLimiter, async (req,res)=>{
  try{
    if(!db) return res.status(500).json({ok:false,error:'Firebase creds missing'})
    const { orgId } = req.params
    const orgSnap = await db.collection('orgs').doc(orgId).get()
    if(!orgSnap.exists) return res.status(404).json({ok:false,error:'Organization not found'})
    const orgData = orgSnap.data()
    if(orgData.ownerUid !== req.user.uid) return res.status(403).json({ok:false,error:'Forbidden: you do not own this organization'})
    const domain = orgData.customDomain
    if(!domain) return res.status(400).json({ok:false,error:'No custom domain set for this org'})
    let verified=false, cnames=[]
    try{ cnames = await dns.resolveCname(domain); verified=cnames.includes(VERIFY_CNAME_TARGET) } catch(err){ if(!['ENODATA','ENOTFOUND'].includes(err.code)) throw err }
    if(!verified){ try{ const txts=await dns.resolveTxt(domain); verified=txts.flat().some(s=>s.includes('certify-verify=')) } catch{} }
    await db.collection('orgs').doc(orgId).set({domainVerified:verified},{merge:true})
    res.json({ok:true,domain,verified,cnames})
  }catch(e){ res.status(500).json({ok:false,error:e?.message||String(e)}) }
})

/* ============== Pesapal subscribe & IPN ============== */
async function subscribeHandler(req,res){
  try{
    if(!db) return res.status(500).json({ok:false,error:'Firebase creds missing'})
    if(!req.user?.uid) return res.status(401).json({ok:false,error:'Unauthorized'})
    const uid=req.user.uid
    const { planId,email,first_name='',last_name='',country_code:rawCountry } = req.body||{}
    if(!planId||!AMOUNT_BY_PLAN[planId]) return res.status(400).json({ok:false,error:'Unknown planId'})
    if(!PESA_IPN_ID) return res.status(500).json({ok:false,error:'Server missing PESA_IPN_ID (register IPN first)'})
    const amount = AMOUNT_BY_PLAN[planId]
    const { token, base, url } = await pesaToken()
    const merchantRef = `sub_${planId}_${uid}_${Date.now()}`
    const country_code = normalizeCountryCode(rawCountry)
    const payload = {
      id: merchantRef,
      currency:'KES',
      amount:Number(amount),
      description:`Certify ${planId.replace('_',' ').toUpperCase()}`,
      callback_url:`${clean(PUBLIC_SITE_URL)}/upgrade?ref=${encodeURIComponent(merchantRef)}`,
      cancellation_url:`${clean(PUBLIC_SITE_URL)}/upgrade?cancel=1`,
      notification_id:PESA_IPN_ID,
      billing_address:{email:email||'guest@example.com',first_name,last_name, ...(country_code?{country_code}:{})}
    }
    const { data } = await axios.post(`${url}/api/Transactions/SubmitOrderRequest`,payload,{headers:{Authorization:`Bearer ${token}`, 'Content-Type':'application/json', Accept:'application/json'}})
    const redirectUrl = data?.redirect_url || data?.order_instructions?.redirect_url || data?.payment_url || null
    if(!redirectUrl) return res.status(502).json({ok:false,error:'Pesapal did not return redirect_url', provider_echo:{has_order_tracking_id:!!data?.order_tracking_id, keys:Object.keys(data||{})}})
    await db.collection('orders').doc(merchantRef).set({type:'subscription',planId,amount,currency:'KES',status:'pending',createdAt:admin.firestore.FieldValue.serverTimestamp(),uid,provider:'pesapal',orderTrackingId:data?.order_tracking_id||null,base},{merge:true})
    res.json({ok:true,baseUsed:base,redirect_url:redirectUrl,order_tracking_id:data?.order_tracking_id,merchant_reference:merchantRef})
  }catch(e){ res.status(500).json({ok:false,error:e?.response?.data||e?.message||String(e)}) }
}

app.post('/api/pesapal/subscribe', authenticate, pesapalLimiter, subscribeHandler)
app.post('/pesapal/createOrder', authenticate, pesapalLimiter, subscribeHandler)

async function handlePesaNotification(params,res){
  try{
    const orderTrackingId = params?.OrderTrackingId || params?.orderTrackingId
    if(!orderTrackingId) return res.status(400).json({ok:false,error:'Missing OrderTrackingId'})
    const { token,url } = await pesaToken()
    const { data: status } = await axios.get(`${url}/api/Transactions/GetTransactionStatus?orderTrackingId=${encodeURIComponent(orderTrackingId)}`,{headers:{Authorization:`Bearer ${token}`,Accept:'application/json'}})
    const mr = String(status?.merchant_reference||'')
    const match = mr.match(/^sub_([^_]+)_(.+?)_\d+$/)
    const planId = match ? match[1]: null, uid = match ? match[2]: null
    const paid = Number(status?.status_code) === 1
    if(paid && db && uid && mr){
      const orderRef=db.collection('orders').doc(mr)
      const orderSnap = await orderRef.get()
      if(orderSnap.exists){
        const finalPlanId = planId || amountToPlanId(status?.amount) || 'pro_monthly'
        const interval = INTERVAL_BY_PLAN[finalPlanId] || 'month'
        await db.collection('users').doc(uid).set({pro:true,planId:finalPlanId,proUntil:addInterval(Date.now(),interval),proSetAt:admin.firestore.FieldValue.serverTimestamp(),lastPayment:{provider:'pesapal',orderTrackingId,merchant_reference:mr,amount:status?.amount,currency:status?.currency||'KES',status:status?.payment_status_description}},{merge:true})
        await orderRef.set({status:'paid',paidAt:admin.firestore.FieldValue.serverTimestamp(),statusPayload:status},{merge:true})
      } else await db.collection('orders').doc(mr).set({status:'failed_unknown_order',statusPayload:status},{merge:true}).catch(()=>{})
    } else await db?.collection('orders').doc(mr||orderTrackingId).set({status:'failed',statusPayload:status},{merge:true}).catch(()=>{})
    if(params?.OrderNotificationType==='IPNCHANGE') return res.json({orderNotificationType:'IPNCHANGE',orderTrackingId,orderMerchantReference:status?.merchant_reference||'',status:200})
    res.json({ok:true,status})
  }catch(e){ res.status(500).json({ok:false,error:e?.response?.data||e?.message||String(e)})}
}
app.get('/pesapal/ipn', ipnLimiter, (req,res)=>handlePesaNotification(req.query,res))
app.post('/pesapal/ipn', ipnLimiter, (req,res)=>handlePesaNotification(req.body,res))

/* ============== Static files & React build fallback ============== */
app.use(express.static(path.join(__dirname,'build')))
app.get('*', (_req,res) => res.sendFile(path.join(__dirname,'build','index.html')))

/* ============== Start server ============== */
app.listen(PORT,()=>console.log(`Server listening on :${PORT}\nAllowed origins: ${allowList.join(', ')}`))
