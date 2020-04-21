module.exports = errors => {
  class WeakPasswordError extends errors.BadRequestError {
    constructor() {
      super('Password is too weak', 'kuzzle-plugin-auth-passport-local.weak-password', 0x0ff001007);
    }

    get name() {
      return this.constructor.name;
    }
  }

  return WeakPasswordError;
};