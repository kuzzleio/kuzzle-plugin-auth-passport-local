module.exports = errors => {
  class ExpiredPasswordError extends errors.KuzzleError {
    constructor() {
      super('Expired password', 403, 'kuzzle-plugin-auth-passport-local.expired-password', 0xff0101);
    }

    get name() {
      return 'ExpiredPasswordError';
    }
  }

  return ExpiredPasswordError;
};