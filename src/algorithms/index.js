/**
 * Dependencies
 */
const SupportedAlgorithms = require('./SupportedAlgorithms')
const RsaKeyPair = require('./RsaKeyPair')

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
 * Export
 */
module.exports = supportedAlgorithms
