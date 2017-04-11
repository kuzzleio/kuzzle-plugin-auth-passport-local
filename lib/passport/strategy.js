const LocalStrategy = require('passport-local').Strategy;

/**
 * @class Strategy
 * @property {object} context
 */
class Strategy {
  /**
   * @param {object} context
   * @constructor
   */
  constructor (context) {
    this.context = context;
  }

  /**
   * @param {string} username
   * @param {string} password
   * @param {function} done
   */
  verify(request, username, password, done) {
    this.context.accessors.users.load(username)
      .then(userObject => {
        if (userObject !== null) {
          let userPassword = null;

          if (userObject.password) {
            userPassword = userObject.password;
          }
          if (userPassword === null && userObject._source && userObject._source.password) {
            userPassword = userObject._source.password;
          }

          if (userPassword) {
            this.context.passwordManager.checkPassword(password, userObject.password || userObject._source.password)
            .then(result => {
              if (result === false) {
                return done(new this.context.errors.ForbiddenError('Login failed'));
              }

              done(null, userObject);
            });
          } else {
            done(new this.context.errors.ForbiddenError('Login failed'));
          }

        }
        else {
          done(new this.context.errors.ForbiddenError('Login failed'));
        }
      })
      .catch(err => done(err));
  }

  load() {
    this.context.accessors.registerStrategy(LocalStrategy, 'local', this, this.verify);
  }
}

module.exports = Strategy;
