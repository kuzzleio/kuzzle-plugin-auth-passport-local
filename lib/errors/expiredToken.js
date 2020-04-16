module.exports = errors => {
  class ExpiredTokenError extends errors.KuzzleError {
    constructor() {
      super('Expired token', 403, 'kuzzle-plugin-auth-passport-local.expired-token', 0xff0102);
    }

    get name() {
      return 'ExpiredTokenError';
    }
  }

  return ExpiredTokenError;
};