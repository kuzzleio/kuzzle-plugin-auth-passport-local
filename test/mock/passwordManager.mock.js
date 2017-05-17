const PasswordManager = require('../../lib/passwordManager');

module.exports = new PasswordManager({
  'algorithm': 'sha512',
  'digest': 'hex'
});