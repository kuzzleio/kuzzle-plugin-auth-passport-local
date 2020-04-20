module.exports = errors => {
  class LoginInPasswordError extends errors.BadRequestError {
    constructor() {
      super('Login in Password', 'kuzzle-plugin-auth-passport-local.login-in-password', 0xff0104);
    }
  }

  return LoginInPasswordError;
};