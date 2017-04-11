const
  isString = require('lodash.isstring'),
  crypto = require('crypto'),
  pipes = require('./config/pipes'),
  PasswordManager = require('./passwordManager'),
  Strategy = require('./passport/strategy'),
  defaultConfig = {
    'secret': null,
    'algorithm': 'sha256',
    'digest': 'hex'
  },
  storageMapping = {
    configuration: {
      properties: {
        configurationValue: {
          type: 'keyword'
        }
      }
    }
  };

/**
 * @class AuthPassportLocal
 * @property {?KuzzlePluginContext} context
 * @property {object} pipes
 * @property {object} configurationRepository
 * @property {object} passwordRepository
 * @property {object} anonymousUser
 * @property {object} routes
 * @property {object} controllers
 */
class AuthPassportLocal {
  /**
   * @constructor
   */
  constructor () {
    this.context = null;
    this.pipes = pipes;
    this.configRepository = null;
    this.passwordRepository = null;
  }

  /**
   * @param {object} customConfig
   * @param {KuzzlePluginContext} context
   * @returns {*}
   */
  init (customConfig, context) {
    let strategy;
    this.config = Object.assign(defaultConfig, customConfig);

    if (!this.config.algorithm) {
      console.error(new Error('plugin-auth-passport-local: The \'algorithm\' attribute is required'));
      return false;
    }
    if (!this.config.digest) {
      console.error(new Error('plugin-auth-passport-local: The \'digest\' attribute is required'));
      return false;
    }

    this.context = context;
    this.configRepository = new this.context.constructors.Repository('configuration');

    return this.context.accessors.storage.bootstrap(storageMapping)
      .then(() => this.configRepository.get('secret'))
      .then(result => {
        if (result && result.configurationValue) {
          this.config.secret = result.configurationValue;
          return Promise.resolve();
        }

        if (!this.config.secret) {
          this.config.secret = crypto.randomBytes(64).toString('hex');
        }

        return this.configRepository.create({_id: 'secret', configurationValue: this.config.secret});
      })
      .then(() => {
        strategy = new Strategy(this.context);
        strategy.load();

        this.context.passwordManager = new PasswordManager(this.config);

        return true;
      });
  }
  /**
   * @param {object<string, *>} user
   * @param {function} callback
   */
  cleanUserCredentials (user, callback) {
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
  }

  /**
   * @param {KuzzleRequest} request
   * @param {function} callback
   */
  encryptCredentials (request, callback) {
    if (request.input.body.password === undefined) {
      // The plugin does not enforce the password in case another plugin is installed
      // @todo: add some configuration check on whether to trigger an error
      return callback(null, request);
    }

    if (!isString(request.input.body.password)) {
      return callback(new this.context.errors.BadRequestError('Missing or invalid given property: password'));
    }

    if (request.input.body.password.trim() === '') {
      return callback(new this.context.errors.BadRequestError('Empty password is not allowed'));
    }

    this.context.passwordManager.encryptPassword(request.input.body.password)
      .then(encryptedPassword => {
        request.input.body.password = encryptedPassword;
        callback(null, request);
      })
      .catch(error => callback(error));
  }
}

module.exports = AuthPassportLocal;
