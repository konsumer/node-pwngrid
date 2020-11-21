const crypto = require('crypto')
const { promisify } = require('util')
const fetch = require('isomorphic-fetch')

const generateKeyPair = promisify(crypto.generateKeyPair)
const b64 = s => Buffer.from(s).toString('base64')

class PwnGrid {
  constructor (privateKey, name = 'nodejs', endpoint = 'https://api.pwnagotchi.ai/api/v1') {
    if (typeof privateKey === 'string') {
      privateKey = crypto.createPrivateKey({ key: privateKey, format: 'pem' })
    }
    this.publicKey = crypto.createPublicKey({ key: privateKey, format: 'pem' })
    this.privateKey = privateKey
    this.endpoint = endpoint
    this.name = name
  }

  // get the address of this identity
  get identity () {
    return `${this.name}@${crypto.createHash('sha256').update(this.publicKey.toString()).digest('hex')}`
  }

  // generate keypair
  static async genkey () {
    const { publicKey, privateKey } = await generateKeyPair('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    })
    return { publicKey, privateKey }
  }

  // Sign some text with private key, return base64
  sign (text) {
    const s5 = crypto.createSign('SHA256')
      .update(text)
      .sign({
        key: this.privateKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING
      })
    return s5.toString('base64')
  }

  // Get a paged list of all the enrolled units, use ?p=2 for pages other than the first one.
  units (page = 1) {
    return this.get(`/units?p=${page}`)
  }

  // Get a list of countries and number of units registered for each
  byCountry () {
    return this.get('/units/by_country')
  }

  // Get information about a unit given its fingerprint.
  unit (fingerprint) {
    return this.get(`/unit/${fingerprint}`)
  }

  // Enroll a unit with its RSA keypair and give it a JWT token for further authenticated requests.
  async enroll (data) {
    const pubkey = this.publicKey.export({ type: 'spki', format: 'pem' })
    const message = {
      identity: this.identity,
      public_key: b64(pubkey),
      signature: this.sign(this.identity)
    }
    if (data) {
      message.data = data
    }
    const { token } = await this.post('/unit/enroll', message)
    this.token = token
    return token
  }

  // Get a paged list of all PwnMAIL inbox messages.
  inbox (page = 1) {
    if (!this.token) {
      throw new Error('This requires a call to enroll()')
    }
    return this.get(`/unit/inbox?p=${page}`)
  }

  // Get a message given its identifier. The content is encrypted and must be decrypted.
  message (id) {
    if (!this.token) {
      throw new Error('This requires a call to enroll()')
    }
    return this.get(`/unit/inbox/${id}`)
  }

  // Mark a message given its identifier, mark can be seen, unseen or deleted
  mark (id, mark) {
    if (!this.token) {
      throw new Error('This requires a call to enroll()')
    }
    return this.get(`/unit/inbox/${id}/${mark}`)
  }

  // Send an encrypted message to a unit by its fingerprint. The content must be signed and encrypted.
  send (fingerprint, message) {
    if (!this.token) {
      throw new Error('This requires a call to enroll()')
    }
    const body = {
      data: 'base64 encoded AES-GCM encrypted data',
      signature: this.sign(message)
    }
    return this.post(`/unit/${fingerprint}/inbox`, body)
  }

  // Fully opted-in units can use this API to report a pwned access point.
  reportAp (essid, bssid) {
    if (!this.token) {
      throw new Error('This requires a call to enroll()')
    }
    return this.post('/unit/report/ap', { essid, bssid })
  }

  // To report multiple access points at once.
  reportAps (aps) {
    return this.post('/unit/report/aps', aps)
  }

  // POST to pwngrid server
  async post (url, body = {}) {
    const headers = {}
    if (this.token) {
      headers.Authorization = `token ${this.token}`
    }
    const r = await fetch(`${this.endpoint}${url}`, { method: 'POST', headers, body: JSON.stringify(body) })
    const j = await r.json()
    if (r.status !== 200) {
      const e = new Error(`Status ${r.status}${j && j.error && (' ' + j.error)}`)
      e.request = e
      throw e
    }
    return j
  }

  // GET from pwngrid server
  async get (url) {
    const headers = {}
    if (this.token) {
      headers.Authorization = `token ${this.token}`
    }
    const r = await fetch(`${this.endpoint}${url}`, { headers })
    if (r.status !== 200) {
      const e = new Error(`Error status ${r.status}`)
      e.request = e
      throw e
    }
    return await r.json()
  }
}

module.exports = PwnGrid
