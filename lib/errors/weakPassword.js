module.exports = errors => {
  class WeakPasswordError extends errors.BadRequestError {
    constructor() {
      super('Password is too weak', 'kuzzle-plugin-auth-passport-local.weak-password', 0xff0106);
    }

    get name() {
      return this.constructor.name;
    }
  }

  return WeakPasswordError;
};