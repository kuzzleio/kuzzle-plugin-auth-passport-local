module.exports = errors => {
  class MustChangePasswordError extends errors.KuzzleError {
    constructor() {
      super('Password change required', 401, 'kuzzle-plugin-auth-passport-local.must-change-password', 0xff0104);
    }

    get name() {
      return this.constructor.name;
    }

  }

  return MustChangePasswordError;
};