module.exports = errors => {
  class ReusedPasswordError extends errors.BadRequestError {
    constructor() {
      super('Cannot reuse ', 'kuzzle-plugin-auth-passport-local.forbidden-reused-password', 0x0ff001006);
    }

    get name() {
      return 'ReusedPasswordError';
    }
  }

  return ReusedPasswordError;
};