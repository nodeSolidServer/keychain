'use strict'

/**
 * Test dependencies
 */
const chai = require('chai')

/**
 * Assertions
 */
chai.should()
let expect = chai.expect

/**
 * Code under test
 */
const RsaKeyPair = require('../src/algorithms/RsaKeyPair')

describe('RsaKeyPair', () => {
  describe('constructor', () => {
    it('throws an error on an invalid hash length', () => {
      let params = { alg: 'RSA222' }

      expect(() => new RsaKeyPair(params))
        .to.throw(/Invalid hash length/)
    })
  })
})
