/**
 * Dependencies
 */
const { crypto } = require('@solid/jose')
const base64url = require('base64url')

/**
 * RsaKeyPair
 */
class RsaKeyPair {

  /**
   * constructor
   *
   * @param params {Object} Options hashmap
   * @param params.alg {string} For example, 'RS256'
   * @param params.modulusLength {number}
   * @param params.publicExponent {BufferSource} For example, a Uint8Array
   * @param params.usages {Array<string>}
   * @param params.crypto {Object} Optional crypto instance to use (for cross-package compatibility)
   */
  constructor (params) {
    let name = 'RSASSA-PKCS1-v1_5'
    let {alg, modulusLength, publicExponent, usages} = params
    let hashLengthValid = alg.match(/(256|384|512)$/)
    let hashLength = hashLengthValid && hashLengthValid.shift()
    let hash = { name: `SHA-${hashLength}` }
    
    // Allow overriding crypto instance for cross-package compatibility
    this.crypto = params.crypto || crypto

    if (!hashLength) {
      throw new Error('Invalid hash length')
    }

    if (!modulusLength) {
      modulusLength = 4096
    }

    if (!publicExponent) {
      publicExponent = new Uint8Array([0x01, 0x00, 0x01])
    }

    if (!usages) {
      usages = ['sign', 'verify']
    }

    this.algorithm = {name, modulusLength, publicExponent, hash}
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
      .then((result) => this.setJwkKeyPair(result))
  }

  /**
   * importKey
   */
  importKey (jwk) {
    let {name, hash} = this.algorithm
    let algorithm = {name, hash}
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
        kid: base64url(Buffer.from(this.crypto.getRandomValues(new Uint8Array(8))))
      }, privateJwk)

      result.publicJwk = Object.assign({
        kid: base64url(Buffer.from(this.crypto.getRandomValues(new Uint8Array(8))))
      }, publicJwk)

      return result
    })
  }
}

/**
 * Export
 */
module.exports = RsaKeyPair
