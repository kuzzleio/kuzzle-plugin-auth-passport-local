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
   * @returns {Promise.<string>}
   */
  encryptPassword (password) {
    const hashedPassword = crypto
      .createHmac(this.config.algorithm, this.config.secret)
      .update(password)
      .digest(this.config.digest);

    return Promise.resolve(hashedPassword);
  }

  /**
   * @param {string} password
   * @param {string} hash
   * @returns {Promise.<string>}
   */
  checkPassword (password, hash) {
    return this.encryptPassword(password)
      .then(function (value) {
        return Promise.resolve(hash === value);
      });
  }
}

module.exports = PasswordManager;
