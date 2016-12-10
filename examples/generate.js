const fs = require('fs')
const KeyChain = require('../src')

let defaults = { alg: 'RS256', modulusLength: 2048 }

let descriptor = {
  token: { sig: defaults },
  id_token: { sig: defaults },
  userinfo: { enc: { alg: 'RS256', usages: ['sign', 'verify'] } }
}

KeyChain.generate(descriptor).then(keys => {
  fs.writeFileSync('keychain.json', JSON.stringify(keys, null, 2))
  console.log(keys)
})
.catch(console.log)



