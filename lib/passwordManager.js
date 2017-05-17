const
  crypto = require('crypto');

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

    this.availableAlgorithms = {
      'RSA-SHA224': 224,
      'RSA-SHA256': 256,
      'RSA-SHA384': 384,
      'RSA-SHA512': 512,
      sha224: 224,
      sha224WithRSAEncryption: 224,
      sha256: 256,
      sha256WithRSAEncryption: 256,
      sha384: 384,
      sha384WithRSAEncryption: 384,
      sha512: 512,
      sha512WithRSAEncryption: 512,
    };
  }

  /**
   * @param {string} password
   * @param {string} salt
   * @returns {string}
   */
  encryptPassword (password, salt) {
    const keylen = this.availableAlgorithms[this.config.algorithm];
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
