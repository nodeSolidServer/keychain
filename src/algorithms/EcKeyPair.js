/**
 * Dependencies
 */
const { crypto } = require('@solid/jose')
const base64url = require('base64url')

/**
 * EcKeyPair
 */
class EcKeyPair {

  /**
   * constructor
   *
   * @param params {Object} Options hashmap
   * @param params.alg {string} For example, 'ES256', 'ES384', 'ES512'
   * @param params.namedCurve {string} For example, 'P-256', 'P-384', 'P-521'
   * @param params.usages {Array<string>}
   * @param params.crypto {Object} Optional crypto instance to use (for cross-package compatibility)
   */
  constructor (params) {
    let name = 'ECDSA'
    let {alg, namedCurve, usages} = params
    
    // Allow overriding crypto instance for cross-package compatibility
    this.crypto = params.crypto || crypto
    
    // Map algorithm to curve and hash
    let algorithmMap = {
      'ES256': { curve: 'P-256', hash: 'SHA-256' },
      'ES384': { curve: 'P-384', hash: 'SHA-384' },
      'ES512': { curve: 'P-521', hash: 'SHA-512' }  // Note: P-521, not P-512
    }

    let algConfig = algorithmMap[alg]
    
    if (!algConfig) {
      throw new Error(`Unsupported EC algorithm: ${alg}`)
    }

    // Use provided namedCurve or default from algorithm
    if (!namedCurve) {
      namedCurve = algConfig.curve
    }

    let hash = { name: algConfig.hash }

    if (!usages) {
      usages = ['sign', 'verify']
    }

    this.alg = alg
    this.algorithm = {name, namedCurve, hash}
    this.extractable = true
    this.usages = usages
  }

  /**
   * generateKey
   */
  generateKey () {
    let {algorithm, extractable, usages} = this

    return this.crypto.subtle
      .generateKey(algorithm, extractable, usages)
      .then(this.setCryptoKeyPair)
      .then(result => this.setJwkKeyPair(result))
  }

  /**
   * importKey
   */
  importKey (jwk) {
    let {name, namedCurve, hash} = this.algorithm
    let algorithm = {name, namedCurve, hash}
    let extractable = true
    let usages = jwk.key_ops

    return this.crypto.subtle
      .importKey('jwk', jwk, algorithm, extractable, usages)
  }

  /**
   * setCryptoKeyPair
   */
  setCryptoKeyPair (cryptoKeyPair) {
    let result = {}

    Object.defineProperty(result, 'privateKey', {
      enumerable: false,
      value: cryptoKeyPair.privateKey
    })

    Object.defineProperty(result, 'publicKey', {
      enumerable: false,
      value: cryptoKeyPair.publicKey
    })

    return result
  }

  /**
   * setJwkKeyPair
   */
  setJwkKeyPair (result) {
    return Promise.all([
      this.crypto.subtle.exportKey('jwk', result.privateKey),
      this.crypto.subtle.exportKey('jwk', result.publicKey)
    ])
    .then(jwks => {
      let [privateJwk, publicJwk] = jwks

      result.privateJwk = Object.assign({
        kid: base64url(Buffer.from(this.crypto.getRandomValues(new Uint8Array(8)))),
        alg: this.alg
      }, privateJwk)

      result.publicJwk = Object.assign({
        kid: base64url(Buffer.from(this.crypto.getRandomValues(new Uint8Array(8)))),
        alg: this.alg
      }, publicJwk)

      return result
    })
  }
}

/**
 * Export
 */
module.exports = EcKeyPair
