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
   * @returns {string}
   */
  encryptPassword (password) {
    return crypto
      .createHmac(this.config.algorithm, this.config.secret)
      .update(password)
      .digest(this.config.digest);
  }

  /**
   * @param {string} password
   * @param {string} hash
   * @returns {boolean}
   */
  checkPassword (password, hash) {
    return hash === this.encryptPassword(password);
  }
}

module.exports = PasswordManager;
