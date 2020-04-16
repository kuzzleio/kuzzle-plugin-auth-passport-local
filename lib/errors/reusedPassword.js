module.exports = errors => {
  class ReusedPasswordError extends errors.BadRequestError {
    constructor() {
      super('Cannot reuse ', 'kuzzle-plugin-auth-passport-local.forbidden-reused-password', 0xff0105);
    }

    get name() {
      return 'ReusedPasswordError';
    }
  }

  return ReusedPasswordError;
};