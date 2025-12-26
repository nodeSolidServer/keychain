/**
 * InvalidDescriptorError
 */
class InvalidDescriptorError extends Error {
  constructor (key, value) {
    super()
    this.message = `Invalid descriptor for key "${key}": ${value}`
  }
}

/**
 * Export
 */
module.exports = InvalidDescriptorError
