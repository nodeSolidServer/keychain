'use strict'

/**
 * Test dependencies
 */
const chai = require('chai')

/**
 * Assertions
 */
chai.use(require('dirty-chai'))
chai.should()
let expect = chai.expect

/**
 * Code under test
 */
const EcKeyPair = require('../src/algorithms/EcKeyPair')
const KeyChain = require('../src/KeyChain')

describe('EcKeyPair', () => {
  describe('constructor', () => {
    it('should set algorithm properties for ES256', () => {
      let params = { alg: 'ES256' }
      let ecKeyPair = new EcKeyPair(params)

      ecKeyPair.alg.should.equal('ES256')
      ecKeyPair.algorithm.name.should.equal('ECDSA')
      ecKeyPair.algorithm.namedCurve.should.equal('P-256')
      ecKeyPair.algorithm.hash.name.should.equal('SHA-256')
      ecKeyPair.extractable.should.equal(true)
      ecKeyPair.usages.should.eql(['sign', 'verify'])
    })

    it('should set algorithm properties for ES384', () => {
      let params = { alg: 'ES384' }
      let ecKeyPair = new EcKeyPair(params)

      ecKeyPair.alg.should.equal('ES384')
      ecKeyPair.algorithm.namedCurve.should.equal('P-384')
      ecKeyPair.algorithm.hash.name.should.equal('SHA-384')
    })

    it('should set algorithm properties for ES512', () => {
      let params = { alg: 'ES512' }
      let ecKeyPair = new EcKeyPair(params)

      ecKeyPair.alg.should.equal('ES512')
      ecKeyPair.algorithm.namedCurve.should.equal('P-521')
      ecKeyPair.algorithm.hash.name.should.equal('SHA-512')
    })

    it('should use provided namedCurve parameter', () => {
      let params = { alg: 'ES256', namedCurve: 'P-256' }
      let ecKeyPair = new EcKeyPair(params)

      ecKeyPair.algorithm.namedCurve.should.equal('P-256')
    })

    it('should use provided usages parameter', () => {
      let params = { alg: 'ES256', usages: ['sign'] }
      let ecKeyPair = new EcKeyPair(params)

      ecKeyPair.usages.should.eql(['sign'])
    })

    it('should throw an error for unsupported algorithm', () => {
      let params = { alg: 'ES128' }

      expect(() => new EcKeyPair(params))
        .to.throw(/Unsupported EC algorithm/)
    })
  })

  describe('generateKey', () => {
    it('should generate ES256 key pair', function () {
      this.timeout(5000)

      let params = { alg: 'ES256', namedCurve: 'P-256' }
      let ecKeyPair = new EcKeyPair(params)

      return ecKeyPair.generateKey().then(result => {
        expect(result).to.be.an('object')
        expect(result.privateKey).to.exist()
        expect(result.publicKey).to.exist()
        expect(result.privateJwk).to.exist()
        expect(result.publicJwk).to.exist()

        // Verify JWK structure
        result.privateJwk.kty.should.equal('EC')
        result.privateJwk.crv.should.equal('P-256')
        result.privateJwk.alg.should.equal('ES256')
        expect(result.privateJwk.kid).to.exist()
        expect(result.privateJwk.d).to.exist()
        expect(result.privateJwk.x).to.exist()
        expect(result.privateJwk.y).to.exist()

        result.publicJwk.kty.should.equal('EC')
        result.publicJwk.crv.should.equal('P-256')
        result.publicJwk.alg.should.equal('ES256')
        expect(result.publicJwk.kid).to.exist()
        expect(result.publicJwk.x).to.exist()
        expect(result.publicJwk.y).to.exist()
        expect(result.publicJwk.d).to.not.exist()

        // Verify CryptoKey properties
        result.privateKey.type.should.equal('private')
        result.privateKey.algorithm.name.should.equal('ECDSA')
        result.publicKey.type.should.equal('public')
        result.publicKey.algorithm.name.should.equal('ECDSA')
      })
    })

    it('should generate ES384 key pair', function () {
      this.timeout(5000)

      let params = { alg: 'ES384', namedCurve: 'P-384' }
      let ecKeyPair = new EcKeyPair(params)

      return ecKeyPair.generateKey().then(result => {
        result.privateJwk.crv.should.equal('P-384')
        result.privateJwk.alg.should.equal('ES384')
        result.publicJwk.crv.should.equal('P-384')
        result.publicJwk.alg.should.equal('ES384')
      })
    })

    it('should generate ES512 key pair', function () {
      this.timeout(5000)

      let params = { alg: 'ES512', namedCurve: 'P-521' }
      let ecKeyPair = new EcKeyPair(params)

      return ecKeyPair.generateKey().then(result => {
        result.privateJwk.crv.should.equal('P-521')
        result.privateJwk.alg.should.equal('ES512')
        result.publicJwk.crv.should.equal('P-521')
        result.publicJwk.alg.should.equal('ES512')
      })
    })
  })

  describe('importKey', () => {
    let publicJwk

    before(function () {
      this.timeout(5000)

      let params = { alg: 'ES256', namedCurve: 'P-256' }
      let ecKeyPair = new EcKeyPair(params)

      return ecKeyPair.generateKey().then(result => {
        publicJwk = result.publicJwk
      })
    })

    it('should import a public JWK', () => {
      let params = { alg: 'ES256' }
      let ecKeyPair = new EcKeyPair(params)

      return ecKeyPair.importKey(publicJwk).then(cryptoKey => {
        cryptoKey.type.should.equal('public')
        cryptoKey.algorithm.name.should.equal('ECDSA')
        cryptoKey.algorithm.namedCurve.should.equal('P-256')
      })
    })
  })

  describe('KeyChain integration', () => {
    const testKeysDescriptor = require('./resources/ES256-keys.json')

    it('should generate ES256 keys through KeyChain', function () {
      this.timeout(10000)

      return KeyChain.generate(testKeysDescriptor.keys.descriptor).then(keychain => {
        expect(keychain.id_token).to.exist()
        expect(keychain.id_token.signing).to.exist()
        expect(keychain.id_token.signing.ES256).to.exist()

        const es256Keys = keychain.id_token.signing.ES256

        // Check JWKs
        expect(es256Keys.privateJwk).to.exist()
        es256Keys.privateJwk.alg.should.equal('ES256')
        es256Keys.privateJwk.kty.should.equal('EC')
        es256Keys.privateJwk.crv.should.equal('P-256')

        expect(es256Keys.publicJwk).to.exist()
        es256Keys.publicJwk.alg.should.equal('ES256')
        es256Keys.publicJwk.kty.should.equal('EC')
        es256Keys.publicJwk.crv.should.equal('P-256')

        // Check CryptoKeys (non-enumerable)
        expect(es256Keys.privateKey).to.exist()
        expect(es256Keys.publicKey).to.exist()

        // Check JWKS
        expect(keychain.jwks).to.exist()
        expect(keychain.jwks.keys).to.be.an('array')
        const es256PublicKey = keychain.jwks.keys.find(k => k.alg === 'ES256')
        expect(es256PublicKey).to.exist()
        es256PublicKey.kty.should.equal('EC')
      })
    })

    it('should generate ES384 keys through KeyChain', function () {
      this.timeout(10000)

      return KeyChain.generate(testKeysDescriptor.keys.descriptor).then(keychain => {
        const es384Keys = keychain.id_token.signing.ES384

        expect(es384Keys).to.exist()
        es384Keys.privateJwk.alg.should.equal('ES384')
        es384Keys.privateJwk.crv.should.equal('P-384')
        es384Keys.publicJwk.alg.should.equal('ES384')
        es384Keys.publicJwk.crv.should.equal('P-384')
      })
    })

    it('should generate ES512 keys through KeyChain', function () {
      this.timeout(10000)

      return KeyChain.generate(testKeysDescriptor.keys.descriptor).then(keychain => {
        const es512Keys = keychain.id_token.signing.ES512

        expect(es512Keys).to.exist()
        es512Keys.privateJwk.alg.should.equal('ES512')
        es512Keys.privateJwk.crv.should.equal('P-521')
        es512Keys.publicJwk.alg.should.equal('ES512')
        es512Keys.publicJwk.crv.should.equal('P-521')
      })
    })

    it('should restore ES256 keychain from data', function () {
      this.timeout(10000)

      let originalKeychain

      return KeyChain.generate({
        signing: { alg: 'ES256', namedCurve: 'P-256' }
      })
        .then(keychain => {
          originalKeychain = keychain
          // Serialize the keychain data - include the full structure
          const data = {
            descriptor: keychain.descriptor,
            signing: keychain.signing  // This contains privateJwk, publicJwk, and the CryptoKeys
          }
          return KeyChain.restore(data)
        })
        .then(restoredKeychain => {
          // After restore, the CryptoKeys should be re-imported
          expect(restoredKeychain).to.exist()
          expect(restoredKeychain.signing).to.exist()
          
          // Check that privateKey and publicKey CryptoKeys were restored
          expect(restoredKeychain.signing.privateKey).to.exist()
          expect(restoredKeychain.signing.publicKey).to.exist()

          restoredKeychain.signing.privateKey.type.should.equal('private')
          restoredKeychain.signing.publicKey.type.should.equal('public')
          
          // Verify JWKs are preserved
          restoredKeychain.signing.privateJwk.alg.should.equal('ES256')
          restoredKeychain.signing.publicJwk.alg.should.equal('ES256')
        })
    })
  })
})
