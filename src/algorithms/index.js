/**
 * Dependencies
 */
const SupportedAlgorithms = require('./SupportedAlgorithms')
const RsaKeyPair = require('./RsaKeyPair')
const EcKeyPair = require('./EcKeyPair')

/**
 * Supported Algorithms
 */
let supportedAlgorithms = new SupportedAlgorithms()

/**
 * RSASSA-PKCS1-v1_5
 */
supportedAlgorithms.define('RS256', 'generateKey', RsaKeyPair)
supportedAlgorithms.define('RS384', 'generateKey', RsaKeyPair)
supportedAlgorithms.define('RS512', 'generateKey', RsaKeyPair)
supportedAlgorithms.define('RS256', 'importKey', RsaKeyPair)
supportedAlgorithms.define('RS384', 'importKey', RsaKeyPair)
supportedAlgorithms.define('RS512', 'importKey', RsaKeyPair)

/**
 * ECDSA
 */
supportedAlgorithms.define('ES256', 'generateKey', EcKeyPair)
supportedAlgorithms.define('ES384', 'generateKey', EcKeyPair)
supportedAlgorithms.define('ES512', 'generateKey', EcKeyPair)
supportedAlgorithms.define('ES256', 'importKey', EcKeyPair)
supportedAlgorithms.define('ES384', 'importKey', EcKeyPair)
supportedAlgorithms.define('ES512', 'importKey', EcKeyPair)


/**
 * Export
 */
module.exports = supportedAlgorithms
