module.exports = errors => {
  class InvalidTokenError extends errors.BadRequestError {
    constructor(message = 'Invalid token') {
      super(message, 'kuzzle-plugin-auth-passport-local.invalid-token', 0x0ff001003);
    }

    get name() {
      return this.constructor.name;
    }

  }

  return InvalidTokenError;
};