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
const { NotSupportedError } = require('../src/errors/index')

describe('NotSupportedError', () => {
  describe('constructor', () => {
    it('composes an "algorithm not supported" error message', done => {
      try {
        throw new NotSupportedError('RS256')
      } catch (err) {
        expect(err.message).to.equal('RS256 is not a supported algorithm')
        done()
      }
    })
  })
})
