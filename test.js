const PwnGrid = require('./index')
const BareTest = require('baretest')
const test = BareTest('pwngrid')
const assert = require('assert')

// PwnGrid.genkey().then(console.log)
const testKey = `
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCz7YT9n2C/S0EM
mDE5AfDqy2kgZEip/tSvylJP1p9fQs/szSwR+7k2SN/8i+QBCGbPbo+0Kftu6+8q
KTRqMjwKJvXbYMOH9p9jsuCExqQUt+P46eYHC+mjADrJmMh0EYCnEvYFD0diTH60
fJf2IRlLa2wJcTxHGIoWNWrqOcNHE57r0OlAdt7JwUeU5B0jHmpkmnUY1SPjQRXb
w/hgBOxjo5C3esQul9lGjVhSnAjSvmiEtgADLtXZa+Z6T8CLC/MVJEjtQPvoeIrw
xRB6s5sFsC1FGlNxmEcx7AJGc/k5pSyQJBP39UF+ZHJmyaKlno3m97Sl1z1oMfQ7
Axfu5L89AgMBAAECggEBAIQC/NRonz87I5rt/w9okS5z18ngSkAPrFTeCM5zFbN6
/bssPe1j11ww08YjjUIEvAntgJobQ1L64Br66G4SNWLteu1ebZfQJtmrYHeKltBs
q2LxmcgJwX3KqVdINaqTPOVYUBEeSK2imkQqNgRr/HcNddLnteYj5wysXKlFgDUg
v8UjgbH4H7ho3piHuYBYo/0IAy8cMF9RW/LHebLGnGb+LmzpA+2xPqwAkbQOlIGS
YHGLQvMrFNUpfuehuCS0g8wrCuN2fl6e6P511VP+5YCQfKUcQwCbEfNdpwqle6+a
Il9RVrAkkzpm3eW0AgLqU+DbKFlhHgUKgea9l+bD8rECgYEA7KNrlzUjdwdodbOo
Q19w5Wnn+Z1Fr4dBsVJZiLQWTsSgKmu9ZLxc9bVxIJYCslQ/F0hbpTBVs/v9XNyY
Hvicg+YRsQtyMkQWBz/a2r3gVLn071825+eAVHf+v4m1bRerwLF6gNROgx7Jxfbv
KPRB4O7eFu5j01DOBpGLIHSwTf8CgYEAwqZAW1JLwENFKzsMWX9vDmpJ3/vEGeV0
WshOXY7XC5tWK3sgX6/2CWyyr8eARPd3Bb3bG7BsREymE8zdDK2l7aLjBdzm/dU1
uxiclj3bYWMlgLH8Kl5s8sxp9Sd0w/Gk0qh8m6vNDwF8WK0tCq6iYlSt33RnLCEv
CNm090MyqsMCgYAGigGIHSTMvjypu/wzWGjTPhj18d2iGxe6oa7tsyRGqvJOGcoT
BY2AELJ+lwaeDOvtZcd6ihpkLdtzfHkLqg0RLANjJBDUyMLfEmmmz8ZqMPVOxA/N
Wr1WGDbG7jRAPn41hfH/q148C1bCDK/RLua/I3qpoY7KoRoAXnc8v1y72wKBgFMB
KFKJDoqHZTihLov/vrEL/ELKjv5oDa0k294jqmplrGJQWCbV13p/Ytd4oKdIS/Yj
1wrAufqKIQwygVUFu8tRebQnVk2KHSaSwTuEV0f5SqXNwHWk3JrRNqH3WGCybBH1
DWYo5gHvJUJ/XsS+YbrC136BmfmEkRUaGYSToEiXAoGATR86DGeT3uhVUxrcfxPc
G2HuzmuVzcEDzMcCm/E4mScoWbZFhK8oZgdOx83/6989TeXvMRrd2tP+9TINv06b
g9+fl6owyYdQ2LlDk/NLyshmu3tqd8a9PRvpUOwkujV6kRioNRBLHZGkCjTkrMXC
sZm9sYXU8PsTBH/7y1wniIQ=
-----END PRIVATE KEY-----
`

const testId = 'nodejs@b28c94b2195c8ed259f0b415aaee3f39b0b2920a4537611499fa044956917a21'

const pwngrid = new PwnGrid(testKey)

test('should have private/public key', async () => {
  assert(pwngrid.privateKey)
  assert(pwngrid.publicKey)
})

test('should be able to get identity', () => {
  assert.strictEqual(testId, pwngrid.identity)
})

test('should be able to get units', async () => {
  const r = await pwngrid.units()
  assert.ok(r.pages)
  assert.ok(r.records)
  assert.ok(r.units)
  assert.strictEqual(r.units.length, 25)
})

test('should be able to get units by country', async () => {
  const r = await pwngrid.byCountry()
  assert.ok(r)
  assert.ok(r.length)
})

// test('should be able to enroll', async () => {
//   const token = await pwngrid.enroll()
//   console.log(token)
// })

// test('should be able to send message', async () => {
//   const r = await pwngrid.send(testId.split('@').pop(), 'Hi from unit-test')
//   assert.ok(r)
// })

// test('should be able to check inbox', async () => {
//   const r = await pwngrid.inbox()
//   assert.ok(r)
//   assert.ok(r.length)
// })

test.run()
