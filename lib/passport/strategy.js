const LocalStrategy = require('passport-local').Strategy;

module.exports = function(context) {
  this.context = context;

  this.verify = function(request, username, password, done) {
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
  };

  this.load = function() {
    this.context.accessors.registerStrategy(LocalStrategy, 'local', this, this.verify);
  };
};
