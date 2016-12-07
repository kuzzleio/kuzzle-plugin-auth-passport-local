var
  _ = require('lodash'),
  pipes = require('./config/pipes'),
  PasswordManager = require('./passwordManager'),
  Strategy = require('./passport/strategy');

/**
 * @constructor
 */
function AuthPassportLocal () {
  this.isDummy = true;
  this.context = {};
  this.pipes = pipes;

  this.init = function (config, context, isDummy) {
    var strategy;

    if (!config) {
      console.error(new Error('plugin-auth-passport-local: A configuration is required for plugin kuzzle-plugin-auth-passport-local'));
      return false;
    }
    if (!config.secret) {
      console.error(new Error('plugin-auth-passport-local: The \'secret\' attribute is required'));
      return false;
    }
    if (!config.algorithm) {
      console.error(new Error('plugin-auth-passport-local: The \'algorithm\' attribute is required'));
      return false;
    }
    if (!config.digest) {
      console.error(new Error('plugin-auth-passport-local: The \'digest\' attribute is required'));
      return false;
    }

    this.isDummy = isDummy;
    this.context = context;

    this.context.passwordManager = new PasswordManager(config);

    strategy = new Strategy(this.context);
    strategy.load();

    return this;
  };

  this.cleanUserCredentials = function(user, callback) {
    try {
      if (user._source !== undefined) {
        delete user._source.password;
      }
      delete user.password;
      callback(null, user);
    }
    catch (error) {
      callback(error);
    }
  };

  this.encryptCredentials = function(request, callback) {
    if (request.input.body.password === undefined) {
      // The plugin does not enforce the password in case another plugin is installed
      // @todo: add some configuration check on whether to trigger an error
      return callback(null, request);
    }

    if (!_.isString(request.input.body.password)) {
      return callback(new this.context.errors.BadRequestError('Missing or invalid given property: password'));
    }

    if (request.input.body.password.trim() === '') {
      return callback(new this.context.errors.BadRequestError('Empty password is not allowed'));
    }

    this.context.passwordManager.encryptPassword(request.input.body.password)
      .then(encryptedPassword => {
        var pjson = require('../package.json');

        request.input.body.password = encryptedPassword;

        if (!request.input.metadata) {
          request.input.metadata = {};
        }
        if (request.input.metadata.pipes === undefined) {
          request.input.metadata.pipes = [];
        }

        // add some information back to the user
        request.input.metadata.pipes.push({
          plugin: pjson.name,
          trigger: 'encryptPassword'
        });

        callback(null, request);
      })
      .catch(error => callback(error));
  };
}

module.exports = AuthPassportLocal;
