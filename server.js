const express = require('express')
const crypto  = require('crypto')
const fs      = require('fs')
const path    = require('path')
const app     = express()

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static(path.join(__dirname, 'public')))

// ── Config ──────────────────────────────────────────────────────────────────
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'changeme123'
const API_SECRET     = process.env.API_SECRET     || 'k3gp_api_secret_change_this'
const DB_FILE        = path.join(__dirname, 'data', 'keys.json')

// ── DB helpers ───────────────────────────────────────────────────────────────
function loadDB() {
  try {
    if (!fs.existsSync(path.dirname(DB_FILE))) fs.mkdirSync(path.dirname(DB_FILE), { recursive: true })
    if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({ keys: {} }))
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'))
  } catch { return { keys: {} } }
}

function saveDB(db) {
  try {
    if (!fs.existsSync(path.dirname(DB_FILE))) fs.mkdirSync(path.dirname(DB_FILE), { recursive: true })
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2))
  } catch(e) { console.error('DB save error:', e) }
}

// ── Key generation ───────────────────────────────────────────────────────────
const CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
function randStr(n) {
  return Array.from({ length: n }, () => CHARS[Math.floor(Math.random() * CHARS.length)]).join('')
}
function generateKey(plan) {
  const prefix = plan === 'weekly' ? 'W7' : plan === 'monthly' ? 'MO' : 'PM'
  return `K3GP-${prefix}${randStr(2)}-${randStr(4)}-${randStr(4)}-${randStr(4)}`
}

// ── Auth middleware ───────────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'] || req.body?.adminToken || req.query?.adminToken
  if (token !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Unauthorized' })
  next()
}

function requireApiSecret(req, res, next) {
  const secret = req.headers['x-api-secret']
  if (secret !== API_SECRET) return res.status(401).json({ error: 'Unauthorized' })
  next()
}

// ════════════════════════════════════════════════════════════════════════════
// APP API — called by K3GP Studio electron app
// ════════════════════════════════════════════════════════════════════════════

// Validate a key (called on every app launch)
app.post('/api/validate', requireApiSecret, (req, res) => {
  const { key, hwid } = req.body
  if (!key || !hwid) return res.json({ valid: false, reason: 'Missing key or hwid.' })

  const db = loadDB()
  const entry = db.keys[key]

  if (!entry) return res.json({ valid: false, reason: 'Invalid license key.' })
  if (entry.revoked) return res.json({ valid: false, reason: 'This license has been revoked.' })

  // Check expiry
  if (entry.plan !== 'perm' && entry.expiresAt) {
    if (Date.now() > entry.expiresAt) {
      return res.json({ valid: false, reason: `Your ${entry.plan} license has expired.` })
    }
  }

  // HWID lock
  if (!entry.hwid) {
    // First activation — lock to this machine
    entry.hwid = hwid
    entry.activatedAt = Date.now()
    db.keys[key] = entry
    saveDB(db)
    return res.json({ valid: true, plan: entry.plan, firstActivation: true })
  }

  if (entry.hwid !== hwid) {
    return res.json({ valid: false, reason: 'This key is already activated on a different machine.' })
  }

  return res.json({ valid: true, plan: entry.plan })
})

// ════════════════════════════════════════════════════════════════════════════
// ADMIN API — called by dashboard
// ════════════════════════════════════════════════════════════════════════════

// Get all keys
app.get('/admin/api/keys', requireAdmin, (req, res) => {
  const db = loadDB()
  res.json({ keys: db.keys })
})

// Generate new keys
app.post('/admin/api/generate', requireAdmin, (req, res) => {
  const { plan, count } = req.body
  if (!['weekly','monthly','perm'].includes(plan)) return res.status(400).json({ error: 'Invalid plan' })
  const n = Math.min(parseInt(count) || 1, 100)
  const db = loadDB()
  const generated = []

  for (let i = 0; i < n; i++) {
    const key = generateKey(plan)
    const daysValid = plan === 'weekly' ? 7 : plan === 'monthly' ? 30 : null
    db.keys[key] = {
      plan,
      createdAt: Date.now(),
      expiresAt: daysValid ? Date.now() + daysValid * 86400000 : null,
      hwid: null,
      activatedAt: null,
      revoked: false,
      note: req.body.note || ''
    }
    generated.push(key)
  }

  saveDB(db)
  res.json({ generated })
})

// Revoke a key
app.post('/admin/api/revoke', requireAdmin, (req, res) => {
  const { key } = req.body
  const db = loadDB()
  if (!db.keys[key]) return res.status(404).json({ error: 'Key not found' })
  db.keys[key].revoked = true
  saveDB(db)
  res.json({ success: true })
})

// Delete a key entirely
app.post('/admin/api/delete', requireAdmin, (req, res) => {
  const { key } = req.body
  const db = loadDB()
  if (!db.keys[key]) return res.status(404).json({ error: 'Key not found' })
  delete db.keys[key]
  saveDB(db)
  res.json({ success: true })
})

// Reset HWID (let key activate on a new machine)
app.post('/admin/api/reset-hwid', requireAdmin, (req, res) => {
  const { key } = req.body
  const db = loadDB()
  if (!db.keys[key]) return res.status(404).json({ error: 'Key not found' })
  db.keys[key].hwid = null
  db.keys[key].activatedAt = null
  saveDB(db)
  res.json({ success: true })
})

// Unrevoke a key
app.post('/admin/api/unrevoke', requireAdmin, (req, res) => {
  const { key } = req.body
  const db = loadDB()
  if (!db.keys[key]) return res.status(404).json({ error: 'Key not found' })
  db.keys[key].revoked = false
  saveDB(db)
  res.json({ success: true })
})

// Update note on a key
app.post('/admin/api/note', requireAdmin, (req, res) => {
  const { key, note } = req.body
  const db = loadDB()
  if (!db.keys[key]) return res.status(404).json({ error: 'Key not found' })
  db.keys[key].note = note
  saveDB(db)
  res.json({ success: true })
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => console.log(`K3GP Auth Server running on port ${PORT}`))
