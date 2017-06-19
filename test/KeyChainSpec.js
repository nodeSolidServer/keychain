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
const KeyChain = require('../src/index')

const testKeys = require('./resources/keys.json')

describe('KeyChain', () => {
  describe('constructor', () => {
    it('uses data as the descriptor if descriptor property is missing', () => {
      let data = {}

      let keys = new KeyChain(data)

      expect(keys.descriptor).to.equal(data)
    })
  })

  describe('static restore()', () => {
    it('imports key data into a new KeyChain instance', () => {
      return KeyChain.restore(testKeys.keys)
        .then(keys => {
          expect(keys).to.be.an.instanceof(KeyChain)
          expect(keys.descriptor).to.exist()
          expect(keys.jwks).to.exist()
        })
    })
  })

  describe('static generate()', () => {
    const descriptor = {
      "id_token": {
        "signing": {
          "RS256": {
            "alg": "RS256",
            "modulusLength": 2048
          },
          "RS512": {
            "alg": "RS512",
            "modulusLength": 2048
          }
        },
        "encryption": {}
      },
      "token": {
        "signing": {
          "RS256": {
            "alg": "RS256",
            "modulusLength": 2048
          },
          "RS384": {
            "alg": "RS384",
            "modulusLength": 2048
          }
        },
        "encryption": {}
      }
    }

    it('should generate a new key chain using a given descriptor', () => {
      return KeyChain.generate(descriptor)
        .then(keys => {
          expect(keys).to.be.an.instanceof(KeyChain)
          expect(keys.descriptor).to.exist()
          expect(keys.jwks).to.exist()
        })
    })
  })
})
