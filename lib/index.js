const
  isString = require('lodash.isstring'),
  crypto = require('crypto'),
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
    },
    users: {
      properties: {
        login: {
          type: 'keyword'
        },
        password: {
          type: 'keyword'
        }
      }
    }
  };

/**
 * @class AuthenticationPlugin
 */
class AuthenticationPlugin {
  /**
   * @constructor
   */
  constructor () {
    this.context = null;
    this.configRepository = null;
    this.strategy = null;
  }

  /**
   * @param {object} customConfig
   * @param {KuzzlePluginContext} context
   * @returns {*}
   */
  init (customConfig, context) {
    this.config = Object.assign(defaultConfig, customConfig);

    if (!this.config.algorithm) {
      console.error(new Error('plugin-auth-passport-local: The \'algorithm\' attribute is required'));
      return false;
    }
    if (!this.config.digest) {
      console.error(new Error('plugin-auth-passport-local: The \'digest\' attribute is required'));
      return false;
    }

    this.initStrategies();

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
        this.context.passwordManager = new PasswordManager(this.config);

        this.strategy = new Strategy(this.context, this.getUsersRepository());
        //this.strategy.load();

        return true;
      });
  }

  initStrategies () {
    this.strategies = {
      local: {
        config: {
          constructor: Strategy,
          strategyOptions: {},
          authenticateOptions: {
            scope: []
          },
          fields: ['login', 'password'],
          verify: 'verify'
        },
        methods: {
          exists: 'exists',
          validate: 'validate',
          create: 'create',
          update: 'update',
          delete: 'delete',
          getInfo: 'getInfo'
        }
      }
    };
  }

  /**
   * @param {KuzzleRequest} request
   * @param {object} credentials
   * @param {string} userId
   * @returns {Promise}
   */
  validate (request, credentials, userId) {
    return this.getUsersRepository().search({
      query: {
        match: {
          login: credentials.username
        }
      } }, 0, 1)
      .then(result => {
        if (!result.total) {
          return Promise.resolve(true);
        }

        if (userId !== result.hits[0]._id) {
          return Promise.reject(new Error('ERROR: Corresponding Kuzzle id was not found'));
        }

        return Promise.resolve(true);
      });
  }

  /**
   * @param {KuzzleRequest} request
   * @param {string} userId
   * @returns {Promise.<boolean>}
   */
  exists (request, userId) {
    return this.getUsersRepository().get(userId)
      .then(result => result !== null);
  }

  /**
   * @param {KuzzleRequest} request
   * @param {Array} credentials
   * @param {string} userId
   * @returns {Promise}
   */
  verify (request, credentials, userId) {
    return this.exists(request, userId)
      .then(exists => {
        if (!exists) {
          return Promise.reject(new Error('User doesn\'t exists'));
        }

        return this.getUsersRepository().get(userId);
      })
      .then(() => {
        return new Promise((resolve, reject) => {
          this.strategy.verify(request, userId, credentials[1], (err, result) => {
            if (err) {
              reject(err);
            }

            resolve(result);
          });
        });
      });
  }

  /**
   * @param {KuzzleRequest} request
   * @param {object} credentials
   * @param {string} userId
   * @returns {Promise}
   */
  create (request, credentials, userId) {
    return this.exists(request, userId)
      .then(exists => {
        if (exists) {
          return Promise.reject(new Error('User already exists'));
        }

        return this.context.passwordManager.encryptPassword(credentials.password)
          .then(encryptedPassword => {
            return this.getUsersRepository().create({
              _id: userId,
              login: credentials.username,
              password: encryptedPassword
            });
          });
      });
  }

  /**
   * @param {KuzzleRequest} request
   * @param {object} credentials
   * @param {string} userId
   * @returns {Promise}
   */
  update (request, credentials, userId) {
    return this.getUsersRepository().update(
      Object.assign({ _id: userId }, request.body)
    );
  }

  /**
   * @param {KuzzleRequest} request
   * @param {string} userId
   * @returns {Promise}
   */
  delete (request, userId) {
    return this.exists(request, userId)
      .then(exists => {
        if (!exists) {
          return Promise.resolve();
        }

        return this.getUsersRepository().delete(userId);
      });
  }

  /**
   * @param {KuzzleRequest} request
   * @param {string} userId
   * @returns {Promise}
   */
  getInfo (request, userId) {
    return this.getUsersRepository().get(userId)
      .then(userObject => {
        if (userObject) {
          return new Promise((resolve, reject) => {
            this.cleanUserCredentials(userObject, (err, result) => {
              if (err) {
                reject(err);
              }

              resolve(result);
            });
          });
        }

        return userObject;
      });
  }

  /**
   * @returns {object}
   */
  getUsersRepository () {
    return new this.context.constructors.Repository('users');
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

module.exports = AuthenticationPlugin;
