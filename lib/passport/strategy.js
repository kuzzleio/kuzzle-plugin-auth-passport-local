var
  LocalStrategy = require('passport-local').Strategy;

module.exports = function(context) {
  this.context = context;

  this.verify = function(username, password, done) {
    this.context.accessors.users.load(username)
      .then(userObject => {
        if (userObject !== null) {
          this.context.passwordManager.checkPassword(password, userObject.password || userObject._source.password)
            .then(result => {
              if (result === false) {
                return done(new this.context.errors.ForbiddenError('Login failed'));
              }

              done(null, userObject);
            });
        }
        else {
          done(new this.context.errors.ForbiddenError('Login failed'));
        }
      })
      .catch(err => done(err));
  };

  this.load = function() {
    this.context.accessors.passport.use(new LocalStrategy(this.verify));
  };
};
