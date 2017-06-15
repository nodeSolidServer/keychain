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
const SupportedAlgorithms = require('../src/algorithms/SupportedAlgorithms')

describe('SupportedAlgorithms', () => {
  describe('constructor', () => {
    it('initializes empty operations objects', () => {
      let sa = new SupportedAlgorithms()

      expect(sa.importKey).to.eql({})
      expect(sa.generateKey).to.eql({})
    })
  })

  describe('static operations getter', () => {
    it('should return the list of operations', () => {
      expect(SupportedAlgorithms.operations)
        .to.eql([ 'importKey', 'generateKey' ])
    })
  })

  describe('normalize()', () => {
    let supportedAlgorithms

    beforeEach(() => {
      supportedAlgorithms = new SupportedAlgorithms()
    })

    it('should return an error for an unsupported operation', () => {
      let result = supportedAlgorithms.normalize('invalidOp', 'RS256')

      expect(result).to.be.an.instanceof(Error)
      expect(result.message).to.equal("Operation 'invalidOp' is not supported")
    })

    it('should return an error for an unsupported algorithm', () => {
      let result = supportedAlgorithms.normalize('generateKey', 'invalidAlg')

      expect(result).to.be.an.instanceof(Error)
      expect(result.message).to.equal('invalidAlg is not a supported algorithm')
    })
  })
})
