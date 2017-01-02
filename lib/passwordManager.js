var
  crypto = require('crypto');

/**
 * @param {object} config
 * @constructor
 */
function PasswordManager (config) {
  this.encryptPassword = function (password) {
    var hashedPassword = crypto.createHmac(config.algorithm, config.secret).update(password).digest(config.digest);
    return Promise.resolve(hashedPassword);
  };

  this.checkPassword = function (password, hash) {
    return this.encryptPassword(password)
      .then(function (value) {
        return Promise.resolve(hash === value);
      });
  };
}

module.exports = PasswordManager;
