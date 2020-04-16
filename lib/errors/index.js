module.exports = errors => Object.assign({}, errors, {
  ExpiredPasswordError: require('./expiredPassword')(errors),
  ExpiredTokenError: require('./expiredToken')(errors),
  InvalidTokenError: require('./invalidToken')(errors),
  MustChangePasswordError: require('./mustChangePassword')(errors),
  ReusedPasswordError: require('./reusedPassword')(errors),
  WeakPasswordError: require('./weakPassword')(errors)
});
