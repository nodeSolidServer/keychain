const data = require('../keychain.json')
const KeyChain = require('../src/KeyChain')


KeyChain.restore(data).then(keys => console.log(keys.token.sig.publicKey)).catch(console.log)
