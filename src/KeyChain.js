/**
 * Dependencies
 */
const supportedAlgorithms = require('./algorithms')
const InvalidDescriptorError = require('./errors/InvalidDescriptorError')

/**
 * KeyChain
 */
class KeyChain {

  /**
   * constructor
   * 
   * @param data {Object} Keychain data
   * @param options {Object} Optional configuration
   * @param options.crypto {Object} Optional crypto instance for cross-package compatibility
   */
  constructor (data, options = {}) {
    // use data as the descriptor if descriptor property is missing
    if (!data.descriptor) {
      data = { descriptor: data }
    }

    Object.assign(this, data)
    
    // Store crypto instance if provided
    this._crypto = options.crypto
  }

  /**
   * generate
   */
  static generate (descriptor) {
    let keys = new KeyChain(descriptor)
    return keys.rotate()
  }

  /**
   * generateKey
   *
   * @param {Object} params
   * @return {Promise}
   */
  static generateKey (params, crypto) {
    let normalizedAlgorithm = supportedAlgorithms.normalize('generateKey', params.alg)

    if (normalizedAlgorithm instanceof Error) {
      return Promise.reject(normalizedAlgorithm)
    }

    let algorithm = new normalizedAlgorithm({...params, crypto})

    return algorithm.generateKey()
  }

  /**
   * importKey
   *
   * @param {Object} params
   * @param {Object} jwk
   * @return {Promise}
   */
  static importKey (jwk, crypto) {
    let {alg} = jwk
    let normalizedAlgorithm = supportedAlgorithms.normalize('importKey', alg)

    if (normalizedAlgorithm instanceof Error) {
      return Promise.reject(normalizedAlgorithm)
    }

    let algorithm = new normalizedAlgorithm({alg, crypto})

    return algorithm.importKey(jwk)
  }

  /**
   * restore
   * 
   * @param data {Object} Keychain data
   * @param options {Object} Optional configuration
   * @param options.crypto {Object} Optional crypto instance for cross-package compatibility
   */
  static restore (data, options) {
    let keys = new KeyChain(data, options)
    return keys.importKeys().then(() => keys)
  }

  /**
   * importKeys
   */
  importKeys ({props, object, container, descriptor} = {}) {
    if (!descriptor) { descriptor = this.descriptor }
    if (!props) { props = Object.keys(descriptor) }
    if (!object) { object = this }

    // import key
    if (props.includes('alg')) {
      return KeyChain.importKey(object, this._crypto).then(cryptoKey => {
        if (cryptoKey.type === 'private' && !container.privateKey) {
          Object.defineProperty(container, 'privateKey', {
            enumerable: false,
            value: cryptoKey
          })
        }

        if (cryptoKey.type === 'public' && !container.publicKey) {
          Object.defineProperty(container, 'publicKey', {
            enumerable: false,
            value: cryptoKey
          })
        }
      })

    // import key pair structure (has privateJwk and publicJwk)
    } else if (props.includes('privateJwk') && props.includes('publicJwk')) {
      // Import both private and public keys
      return Promise.all([
        KeyChain.importKey(object.privateJwk, this._crypto),
        KeyChain.importKey(object.publicJwk, this._crypto)
      ]).then(([privateKey, publicKey]) => {
        if (!object.privateKey) {
          Object.defineProperty(object, 'privateKey', {
            enumerable: false,
            value: privateKey
          })
        }

        if (!object.publicKey) {
          Object.defineProperty(object, 'publicKey', {
            enumerable: false,
            value: publicKey
          })
        }
      })

    // recurse
    } else {
      return Promise.all(
        props.map(name => {
          let subDescriptor = descriptor[name]
          let subObject = object[name]
          let subProps = Object.keys(subObject)
          //console.log('RECURSE WITH', name, subDescriptor, subObject, subProps)

          return this.importKeys({
            descriptor: subDescriptor,
            object: subObject,
            container: object,
            props: subProps
          })
        })
      )
    }
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
          return KeyChain.generateKey(params, this._crypto).then(result => {
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
          throw new InvalidDescriptorError(key, params)
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
