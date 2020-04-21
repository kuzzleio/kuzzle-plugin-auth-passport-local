module.exports = errors => {
  class LoginInPasswordError extends errors.BadRequestError {
    constructor() {
      super('Login in Password', 'kuzzle-plugin-auth-passport-local.login-in-password', 0x0ff001004);
    }
  }

  return LoginInPasswordError;
};