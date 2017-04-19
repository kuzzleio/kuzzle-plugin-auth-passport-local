const PasswordManager = require('../../lib/passwordManager');

module.exports = new PasswordManager({
  'secret': '93f6e71fcac1ea14277fec2897e8d59ec80cecec3ca433e519ead94a2a68ace8ed4047e7b32833c7d9cccf4453eab08f9a162b1b123f9aa2c78570603d49bf1a',
  'algorithm': 'sha256',
  'digest': 'hex'
});