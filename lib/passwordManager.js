const crypto = require('crypto');

/**
 * @class PasswordManager
 */
class PasswordManager {
  /**
   * @param {object} config
   * @constructor
   */
  constructor (config) {
    this.config = config;
  }

  /**
   * @param {string} password
   * @param {string} salt
   * @returns {string}
   */
  encryptPassword (password, salt) {
    const keylen = this.config.algorithm === 'sha256' ? 256 : 512;
    return crypto.pbkdf2Sync(password, salt, 10000, keylen, this.config.algorithm).toString(this.config.digest);
  }

  /**
   * @param {string} password
   * @param {string} salt
   * @param {string} hash
   * @returns {boolean}
   */
  checkPassword (password, salt, hash) {
    return hash === this.encryptPassword(password, salt);
  }
}

module.exports = PasswordManager;
