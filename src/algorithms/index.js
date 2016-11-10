/**
 * Dependencies
 */
const RegisteredAlgorithms = require('./RegisteredAlgorithms')
const RsaKeyPair = require('./RsaKeyPair')

/**
 * Registered Algorithms
 */
let registeredAlgorithms = new RegisteredAlgorithms()

/**
 * RSASSA-PKCS1-v1_5
 */
registeredAlgorithms.define('RS256', RsaKeyPair)
registeredAlgorithms.define('RS384', RsaKeyPair)
registeredAlgorithms.define('RS512', RsaKeyPair)

/**
 * Export
 */
module.exports = registeredAlgorithms
