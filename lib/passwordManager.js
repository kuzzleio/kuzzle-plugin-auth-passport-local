const
  crypto = require('crypto');

/**
 * @class PasswordManager
 */
class PasswordManager {
  /**
   * @param {object} config
   * @param {object} context
   * @constructor
   */
  constructor (config, context) {
    this.config = config;
    this.context = context;

    this.availableAlgorithms = {
      'RSA-SHA1': 40,
      'RSA-SHA224': 224,
      'RSA-SHA256': 256,
      'RSA-SHA384': 384,
      'RSA-SHA512': 512,
      sha1: 40,
      sha1WithRSAEncryption: 40,
      sha224: 224,
      sha224WithRSAEncryption: 224,
      sha256: 256,
      sha256WithRSAEncryption: 256,
      sha384: 384,
      sha384WithRSAEncryption: 384,
      sha512: 512,
      sha512WithRSAEncryption: 512
    };
  }

  /**
   * @param {string} password
   * @param {string} salt
   * @param {string} [algorithm] - encryption algorithm, defaults to the one set in the config
   * @param {boolean} [stretching] - (de)activate key stretching
   * @param {string} encryption
   * @returns {Promise.<string>}
   */
  encryptPassword (password, salt, algorithm = this.config.algorithm, stretching = this.config.stretching, encryption = this.config.encryption) {
    const keylen = this.availableAlgorithms[algorithm];

    if (keylen === undefined) {
      // encryption algorithm deliberately absent from the error message
      return Promise.reject(new this.context.errors.BadRequestError('Unknown encryption algorithm'));
    }

    return new Promise((resolve, reject) => {
      if (stretching) {
        crypto.pbkdf2(password, salt, 10000, keylen, algorithm, (err, key) => {
          if (err) {
            return reject(err);
          }

          resolve(key.toString(this.config.digest));
        });
      }
      else if (encryption === 'hmac') {
        resolve(crypto.createHmac(algorithm, salt).update(password).digest(this.config.digest));
      }
      else if (encryption === 'hash') {
        const saltedPassword = salt !== '' ? `${salt}:${password}` : password;

        resolve(crypto.createHash(algorithm).update(saltedPassword).digest(this.config.digest));
      } else {
        return Promise.reject(new this.context.errors.BadRequestError('Unknown encryption type'));
      }
    });
  }

  /**
   * @param {string} password
   * @param {Object} user document
   * @returns {Promise.<boolean>}
   */
  checkPassword (password, user) {
    return this.encryptPassword(password, user.userSalt, user.algorithm, user.stretching, user.encryption || 'hmac')
      .then(encrypted => user.userPassword === encrypted);
  }
}

module.exports = PasswordManager;
