const KeyChain = require('../src')

let defaults = { alg: 'RS256', modulusLength: 2048 }

let keychain = new KeyChain({
  token: { sig: defaults },
  id_token: { sig: defaults },
  userinfo: { enc: { alg: 'RS256', usages: ['sign', 'verify'] } }
})

keychain.rotate()
  .then(console.log)
  .catch(console.log)



