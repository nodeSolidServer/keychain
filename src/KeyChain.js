/**
 * Dependencies
 */
const crypto = require('webcrypto')
const base64url = require('base64url')
const registeredAlgorithms = require('./algorithms')

/**
 * KeyChain
 */
class KeyChain {

  /**
   * constructor
   */
  constructor (descriptor, keys) {
    this.descriptor = descriptor
    Object.assign(this, keys)
  }

  /**
   * generateKey
   *
   * @param {Object} params
   * @return {Promise}
   */
  static generateKey (params) {
    let normalizedAlgorithm = registeredAlgorithms.normalize(params.alg)

    if (normalizedAlgorithm instanceof Error) {
      return Promise.reject(normalizedAlgorithm)
    }

    let algorithm = new normalizedAlgorithm(params)

    return algorithm.generateKey()
  }

  /**
   * rotate
   *
   * @param {Object} context
   * @returns {Promise}
   */
  rotate ({source, container, jwks} = {}) {

    // initial call requires no arguments
    // these values are passed when recursing
    if (!source) { source = this.descriptor }
    if (!container) { container = this }
    if (!jwks) { jwks = this.jwks = { keys: [] } }

    // do as much in parallel as possible
    return Promise.all(
      Object.keys(source).map(key => {
        let params = source[key]

        // generate key(pair), assign resulting object to keychain,
        // and add JWK for public key to JWK Set
        if (params.alg) {
          return KeyChain.generateKey(params).then(result => {
            container[key] = result

            if (result.publicJwk) {
              jwks.keys.push(result.publicJwk)
            }
          })

        // recurse
        } else if (typeof params === 'object') {

          if (!container[key]) {
            container[key] = {}
          }

          return this.rotate({
            source: source[key],
            container: container[key],
            jwks
          })

        // invalid descriptor
        } else {
          throw new InvalidDescriptorError(key, value)
        }
      })
    ).then(() => {
      // cache the JSON serialization of the keychain for publication
      this.jwkSet = JSON.stringify(this.jwks)

      // resulting value is the keychain itself
      return this
    })
  }
}

/**
 * Export
 */
module.exports = KeyChain
