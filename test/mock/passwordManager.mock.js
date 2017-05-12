const PasswordManager = require('../../lib/passwordManager');

module.exports = new PasswordManager({
  'algorithm': 'sha256',
  'digest': 'hex'
});