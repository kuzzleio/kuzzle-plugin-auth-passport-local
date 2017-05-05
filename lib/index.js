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
        userId: {
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
      return Promise.reject(new this.context.errors.BadRequestError(`plugin-auth-passport-local: The 'algorithm' attribute is required`));
    }
    if (!this.config.digest) {
      return Promise.reject(new this.context.errors.BadRequestError(`plugin-auth-passport-local: The 'digest' attribute is required`));
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

        return Promise.resolve();
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
          fields: ['login', 'password']
        },
        methods: {
          create: 'create',
          delete: 'delete',
          exists: 'exists',
          getInfo: 'getInfo',
          update: 'update',
          validate: 'validate',
          verify: 'verify'
        }
      }
    };
  }

  /**
   * @param {KuzzleRequest} request
   * @param {object} credentials
   * @param {string} userId
   * @param {boolean} isUpdate
   * @returns {Promise<boolean>}
   */
  validate (request, credentials, userId, isUpdate) {
    if (isUpdate && !credentials.username) {
      return Promise.resolve(true);
    }

    if (!credentials.username) {
      return Promise.reject(new this.context.errors.BadRequestError('Username is a mandatory field for authentication strategy "local".'));
    }

    if (isUpdate && !credentials.password) {
      return Promise.reject(new this.context.errors.BadRequestError('Username is a mandatory field for authentication strategy "local".'));
    }

    if (credentials.userId) {
      return Promise.reject(new this.context.errors.BadRequestError('userId cannot be specified in credentials.'));
    }

    return this.getUsersRepository().get(credentials.username)
      .then(result => {
        if (result === null) {
          return Promise.resolve(true);
        }

        if (userId !== result.userId) {
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
    return this.getCredentialsFromUserId(userId)
      .then(credentials => credentials !== null);
  }

  /**
   * @param {KuzzleRequest} request
   * @param {string} username
   * @param {string} password
   * @returns {Promise}
   */
  verify (request, username, password) {
    return this.getUsersRepository().get(username)
      .then(result => {
        if (result === null) {
          return Promise.resolve({message: 'wrong username or password'});
        }

        if (!this.passwordManager.checkPassword(password, result.userPassword)) {
          return Promise.resolve({message: 'wrong username or password'});
        }

        return Promise.resolve(result.userId);
      });
  }

  /**
   * @param {KuzzleRequest} request
   * @param {object} credentials
   * @param {string} userId
   * @returns {Promise}
   */
  create (request, credentials, userId) {
    if (!credentials.password) {
      return Promise.reject(new this.context.errors.BadRequestError('Password needed.'));
    }
    return this.exists(request, userId)
      .then(exists => {
        if (exists) {
          return Promise.reject(new this.context.errors.BadRequestError('A strategy already exists for this user.'));
        }

        return this.getUsersRepository().create({
          _id: credentials.username,
          userId,
          userPassword: this.passwordManager.encryptPassword(credentials.password)
        }, {refresh: 'wait_for'})
          .then(createdDocument => Promise.resolve(this.outputDocument(createdDocument)));
      });
  }

  /**
   * @param {KuzzleRequest} request
   * @param {object} credentials
   * @param {string} userId
   * @returns {Promise}
   */
  update (request, credentials, userId) {
    return this.getCredentialsFromUserId(userId)
      .then(document => {
        if (document === null) {
          return Promise.reject(new this.context.errors.BadRequestError('A strategy does not exist for this user.'));
        }

        if (credentials.password) {
          credentials.userPassword = this.passwordManager.encryptPassword(credentials.password);
          delete credentials.password;
        }

        // To change the username, we have to create a new (complete) document and remove the old one
        if (credentials.username && document._id !== credentials.username) {
          let createdDocument;
          const oldDocumentId = document._id;
          const newDocument = Object.assign(document, credentials);

          newDocument._id = credentials.username;
          delete newDocument.username;

          return this.getUsersRepository().create(newDocument)
            .then(create => {
              createdDocument = create;
              return this.getUsersRepository().delete(oldDocumentId);
            })
            .then(() => Promise.resolve(this.outputDocument(createdDocument)));
        }

        return this.getUsersRepository().update(Object.assign({_id: document._id}, credentials), {refresh: 'wait_for'})
          .then(() => this.getCredentialsFromUserId(userId))
          .then(createdDocument => Promise.resolve(this.outputDocument(createdDocument)));
      });
  }

  /**
   * @param {KuzzleRequest} request
   * @param {string} userId
   * @returns {Promise}
   */
  delete (request, userId) {
    return this.getCredentialsFromUserId(userId)
      .then(document => {
        if (document === null) {
          return Promise.reject(new this.context.errors.BadRequestError('A strategy does not exist for this user.'));
        }

        return this.getUsersRepository().delete(document._id, {refresh: 'wait_for'});
      });
  }

  /**
   * @param {KuzzleRequest} request
   * @param {string} userId
   * @returns {Promise}
   */
  getInfo (request, userId) {
    return this.getCredentialsFromUserId(userId)
      .then(document => {
        if (document === null) {
          return Promise.reject(new this.context.errors.BadRequestError('A strategy does not exist for this user.'));
        }

        return Promise.resolve(this.outputDocument(document));
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
  outputDocument (user) {
    return {
      username: user._id
    };
  }

  getCredentialsFromUserId (userId) {
    return this.getUsersRepository().search({
      query: {
        match: {
          userId
        }
      }
    })
      .then(result => {
        if (result.total === 0) {
          return Promise.resolve(null);
        }

        return Promise.resolve(result.hits[0]);
      });
  }
}

module.exports = AuthenticationPlugin;
