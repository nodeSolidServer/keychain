const fs = require('fs')
const KeyChain = require('../src')
const crypto = require('@trust/webcrypto')

let defaults = { alg: 'RS256', modulusLength: 2048 }

let descriptor = {
  token: { sig: defaults },
  id_token: { sig: defaults },
  userinfo: { enc: { alg: 'RS256', usages: ['sign', 'verify'] } }
}

let kek
crypto.subtle.generateKey(
  {
    name: "AES-GCM",
    length: 256, //can be 128, 192, or 256
  },
  false, //whether the key is extractable (i.e. can be used in exportKey)
  ["encrypt", "decrypt"] // usages
).then(result => {
  kek = result
  console.log(kek)
}).then(() => {
  return KeyChain.generate(descriptor, kek).then(keys => {
    fs.writeFileSync('keychain.json', JSON.stringify(keys, null, 2))
    console.log(keys)
  })
})

.catch(console.log)
