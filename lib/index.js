const
  crypto = require('crypto'),
  PasswordManager = require('./passwordManager'),
  LocalStrategy = require('passport-local').Strategy,
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
        userLogin: {
          type: 'keyword'
        },
        userPassword: {
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
    this.userRepository = null;
    this.passwordManager = null;
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
        this.passwordManager = new PasswordManager(this.config);

        return true;
      });
  }

  initStrategies () {
    this.strategies = {
      local: {
        config: {
          constructor: LocalStrategy,
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
    if (!credentials.username) {
      return Promise.reject(new this.context.errors.BadRequestError('Username is a mandatory field for authentication strategy "local".'));
    }

    return this.getUsersRepository().search({
      query: {
        term: {
          userLogin: credentials.username
        }
      } }, 0, 1)
      .then(result => {
        if (!result.total) {
          return Promise.resolve(true);
        }

        if (userId !== result.hits[0]._id) {
          return Promise.reject(new this.context.errors.BadRequestError(`Login "${credentials.username}" is already used.`));
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
   * @param {string} username
   * @param {string} password
   * @returns {Promise}
   */
  verify (request, username, password) {
    return this.getUsersRepository().search({
      query: {
        term: {
          userLogin: username
        }
      } }, 0, 1)
      .then(result => {
        if (result.total === 0) {
          return Promise.reject(new this.context.errors.ForbiddenError('Login failed'));
        }

        if (!this.passwordManager.checkPassword(password, result.hits[0].userPassword)) {
          return Promise.reject(new this.context.errors.ForbiddenError('Login failed'));
        }

        return Promise.resolve(result.hits[0]._id);
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
          return Promise.reject(new this.context.errors.BadRequestError('A strategy already exists for this userId.'));
        }

        return this.getUsersRepository().create({
          _id: userId,
          userLogin: credentials.username,
          userPassword: this.passwordManager.encryptPassword(credentials.password)
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
      {_id: userId, doc: credentials}
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
          return this.cleanUserCredentials(userObject);
        }

        return null;
      });
  }

  /**
   * @returns {PluginRepository}
   */
  getUsersRepository () {
    if (!this.userRepository) {
      this.userRepository = new this.context.constructors.Repository('users');
    }

    return this.userRepository;
  }

  /**
   * @param {object<string, *>} user
   */
  cleanUserCredentials (user) {
    if (user._source !== undefined) {
      delete user._source.userPassword;
    }
    else if (user.userPassword) {
      delete user.userPassword;
    }

    return user;
  }
}

module.exports = AuthenticationPlugin;
