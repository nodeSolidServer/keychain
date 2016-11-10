/**
 * Dependencies
 */
const {NotSupportedError} = require('../errors')

/**
 * RegisteredAlgorithms
 */
class RegisteredAlgorithms {

  /**
   * define
   *
   * @param {string} name – JWA algorithm name
   * @param {Object} algorithm – Web Crypto API algorithm parameters
   */
  define (name, algorithm) {
    this[name] = algorithm
  }

  /**
   * normalize
   */
  normalize (name) {
    let algorithm = this[name]

    if (!algorithm) {
      return new NotSupportedError(name)
    }

    return algorithm
  }
}

/**
 * Export
 */
module.exports = RegisteredAlgorithms
