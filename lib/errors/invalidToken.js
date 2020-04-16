module.exports = errors => {
  class InvalidTokenError extends errors.BadRequestError {
    constructor(message = 'Invalid token') {
      super(message, 'kuzzle-plugin-auth-passport-local.invalid-token', 0xff0103);
    }

    get name() {
      return this.constructor.name;
    }

  }

  return InvalidTokenError;
};