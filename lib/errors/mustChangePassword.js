module.exports = errors => {
  class MustChangePasswordError extends errors.KuzzleError {
    constructor() {
      super('Password change required', 401, 'kuzzle-plugin-auth-passport-local.must-change-password', 0x0ff001005);
    }

    get name() {
      return this.constructor.name;
    }

  }

  return MustChangePasswordError;
};