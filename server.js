const express = require('express')
const https   = require('https')
const path    = require('path')
const app     = express()

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static(path.join(__dirname, 'public')))

// ── Config ──────────────────────────────────────────────────────────────────
const ADMIN_PASSWORD  = process.env.ADMIN_PASSWORD  || 'changeme123'
const API_SECRET      = process.env.API_SECRET      || 'k3gp_api_secret_change_this'
const JSONBIN_API_KEY = process.env.JSONBIN_API_KEY || ''
const JSONBIN_BIN_ID  = process.env.JSONBIN_BIN_ID  || ''

// ── JSONBin helpers ──────────────────────────────────────────────────────────
function jsonbinRequest(method, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null
    const options = {
      hostname: 'api.jsonbin.io',
      port: 443,
      path: `/v3/b/${JSONBIN_BIN_ID}`,
      method,
      headers: {
        'X-Master-Key': JSONBIN_API_KEY,
        'Content-Type': 'application/json',
        'X-Bin-Versioning': 'false',
      }
    }
    if (data) options.headers['Content-Length'] = Buffer.byteLength(data)
    const req = https.request(options, (res) => {
      let d = ''
      res.on('data', c => d += c)
      res.on('end', () => {
        try { resolve(JSON.parse(d)) }
        catch { reject(new Error('JSONBin parse error')) }
      })
    })
    req.on('error', reject)
    if (data) req.write(data)
    req.end()
  })
}

async function loadDB() {
  const res = await jsonbinRequest('GET')
  return res.record || { keys: {} }
}

async function saveDB(db) {
  await jsonbinRequest('PUT', db)
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
// APP API
// ════════════════════════════════════════════════════════════════════════════

app.post('/api/validate', requireApiSecret, async (req, res) => {
  try {
    const { key, hwid } = req.body
    if (!key || !hwid) return res.json({ valid: false, reason: 'Missing key or hwid.' })

    const db = await loadDB()
    const entry = db.keys[key]

    if (!entry) return res.json({ valid: false, reason: 'Invalid license key.' })
    if (entry.revoked) return res.json({ valid: false, reason: 'This license has been revoked.' })

    if (entry.plan !== 'perm' && entry.expiresAt) {
      if (Date.now() > entry.expiresAt) {
        return res.json({ valid: false, reason: `Your ${entry.plan} license has expired.` })
      }
    }

    if (!entry.hwid) {
      entry.hwid = hwid
      entry.activatedAt = Date.now()
      db.keys[key] = entry
      await saveDB(db)
      return res.json({ valid: true, plan: entry.plan, firstActivation: true })
    }

    if (entry.hwid !== hwid) {
      return res.json({ valid: false, reason: 'This key is already activated on a different machine.' })
    }

    return res.json({ valid: true, plan: entry.plan })
  } catch(e) {
    console.error('validate error:', e)
    res.json({ valid: false, reason: 'Server error. Try again.' })
  }
})

// ════════════════════════════════════════════════════════════════════════════
// ADMIN API
// ════════════════════════════════════════════════════════════════════════════

app.get('/admin/api/keys', requireAdmin, async (req, res) => {
  try {
    const db = await loadDB()
    res.json({ keys: db.keys })
  } catch(e) { res.status(500).json({ error: 'DB error' }) }
})

app.post('/admin/api/generate', requireAdmin, async (req, res) => {
  try {
    const { plan, count, note } = req.body
    if (!['weekly','monthly','perm'].includes(plan)) return res.status(400).json({ error: 'Invalid plan' })
    const n = Math.min(parseInt(count) || 1, 100)
    const db = await loadDB()
    const generated = []

    for (let i = 0; i < n; i++) {
      const key = generateKey(plan)
      const daysValid = plan === 'weekly' ? 7 : plan === 'monthly' ? 30 : null
      db.keys[key] = {
        plan, createdAt: Date.now(),
        expiresAt: daysValid ? Date.now() + daysValid * 86400000 : null,
        hwid: null, activatedAt: null, revoked: false, note: note || ''
      }
      generated.push(key)
    }

    await saveDB(db)
    res.json({ generated })
  } catch(e) { res.status(500).json({ error: 'DB error' }) }
})

app.post('/admin/api/revoke', requireAdmin, async (req, res) => {
  try {
    const { key } = req.body
    const db = await loadDB()
    if (!db.keys[key]) return res.status(404).json({ error: 'Key not found' })
    db.keys[key].revoked = true
    await saveDB(db)
    res.json({ success: true })
  } catch(e) { res.status(500).json({ error: 'DB error' }) }
})

app.post('/admin/api/delete', requireAdmin, async (req, res) => {
  try {
    const { key } = req.body
    const db = await loadDB()
    if (!db.keys[key]) return res.status(404).json({ error: 'Key not found' })
    delete db.keys[key]
    await saveDB(db)
    res.json({ success: true })
  } catch(e) { res.status(500).json({ error: 'DB error' }) }
})

app.post('/admin/api/reset-hwid', requireAdmin, async (req, res) => {
  try {
    const { key } = req.body
    const db = await loadDB()
    if (!db.keys[key]) return res.status(404).json({ error: 'Key not found' })
    db.keys[key].hwid = null
    db.keys[key].activatedAt = null
    await saveDB(db)
    res.json({ success: true })
  } catch(e) { res.status(500).json({ error: 'DB error' }) }
})

app.post('/admin/api/unrevoke', requireAdmin, async (req, res) => {
  try {
    const { key } = req.body
    const db = await loadDB()
    if (!db.keys[key]) return res.status(404).json({ error: 'Key not found' })
    db.keys[key].revoked = false
    await saveDB(db)
    res.json({ success: true })
  } catch(e) { res.status(500).json({ error: 'DB error' }) }
})

app.post('/admin/api/note', requireAdmin, async (req, res) => {
  try {
    const { key, note } = req.body
    const db = await loadDB()
    if (!db.keys[key]) return res.status(404).json({ error: 'Key not found' })
    db.keys[key].note = note
    await saveDB(db)
    res.json({ success: true })
  } catch(e) { res.status(500).json({ error: 'DB error' }) }
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => console.log(`K3GP Auth Server running on port ${PORT}`))
