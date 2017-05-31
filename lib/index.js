const
  crypto = require('crypto'),
  PasswordManager = require('./passwordManager'),
  LocalStrategy = require('passport-local').Strategy,
  defaultConfig = {
    'algorithm': 'sha512',
    'digest': 'hex'
  },
  storageMapping = {
    users: {
      properties: {
        kuid: {
          type: 'keyword'
        },
        userPassword: {
          type: 'keyword'
        },
        userSalt: {
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
    this.strategy = null;
    this.userRepository = null;
    this.passwordManager = null;
  }

  /**
   * @param {object} customConfig
   * @param {KuzzlePluginContext} context
   * @returns {Promise<*>}
   */
  init (customConfig, context) {
    this.config = Object.assign(defaultConfig, customConfig);
    this.passwordManager = new PasswordManager(this.config);

    if (!this.config.algorithm) {
      return Promise.reject(new this.context.errors.BadRequestError(`plugin-auth-passport-local: The 'algorithm' attribute is required`));
    }
    if (!this.passwordManager.availableAlgorithms[this.config.algorithm]) {
      return Promise.reject(new this.context.errors.BadRequestError(`plugin-auth-passport-local: The 'algorithm' attribute must be a valid algorithm; provided "${this.config.algorithm}".`));
    }
    if (!this.config.digest) {
      return Promise.reject(new this.context.errors.BadRequestError(`plugin-auth-passport-local: The 'digest' attribute is required`));
    }

    this.initStrategies();

    this.context = context;

    return this.context.accessors.storage.bootstrap(storageMapping);
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
          fields: ['username', 'password']
        },
        methods: {
          create: 'create',
          delete: 'delete',
          exists: 'exists',
          getById: 'getById',
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
   * @param {string} kuid
   * @param {string} strategy
   * @param {boolean} isUpdate
   * @returns {Promise<boolean>}
   */
  validate (request, credentials, kuid, strategy, isUpdate) {
    if (credentials.kuid) {
      return Promise.reject(new this.context.errors.BadRequestError('kuid cannot be specified in credentials.'));
    }

    if (isUpdate) {
      if (!credentials.username && !credentials.password) {
        return Promise.reject(new this.context.errors.BadRequestError('The request must at least provide one of the fileds: "username" or "password".'));
      }

      return Promise.resolve(true);
    }

    if (!credentials.username) {
      return Promise.reject(new this.context.errors.BadRequestError('The field "username" is mandatory for authentication strategy "local".'));
    }

    if (!credentials.password) {
      return Promise.reject(new this.context.errors.BadRequestError('The field "password" is mandatory for authentication strategy "local".'));
    }

    return this.getUsersRepository().get(credentials.username)
      .then(result => {
        if (result === null) {
          return Promise.resolve(true);
        }

        if (kuid !== result.kuid) {
          return Promise.reject(new this.context.errors.PreconditionError(`Login "${credentials.username}" is already used.`));
        }

        return Promise.resolve(true);
      });
  }

  /**
   * @param {KuzzleRequest} request
   * @param {string} kuid
   * @returns {Promise<boolean>}
   */
  exists (request, kuid) {
    return this.getCredentialsFromUserId(kuid)
      .then(credentials => credentials !== null);
  }

  /**
   * @param {KuzzleRequest} request
   * @param {string} username
   * @param {string} password
   * @returns {Promise<string|{message: string}>}
   */
  verify (request, username, password) {
    return this.getUsersRepository().get(username)
      .then(result => {
        if (result === null) {
          return Promise.resolve({
            kuid: null,
            message: 'wrong username or password'
          });
        }

        if (!this.passwordManager.checkPassword(password, result.userSalt, result.userPassword)) {
          return Promise.resolve({
            kuid: null,
            message: 'wrong username or password'
          });
        }

        return Promise.resolve({
          kuid: result.kuid
        });
      });
  }

  /**
   * @param {KuzzleRequest} request
   * @param {object} credentials
   * @param {string} kuid
   * @returns {Promise<object>}
   */
  create (request, credentials, kuid) {
    if (!credentials.password) {
      return Promise.reject(new this.context.errors.BadRequestError('Password needed.'));
    }
    return this.exists(request, kuid)
      .then(exists => {
        if (exists) {
          return Promise.reject(new this.context.errors.PreconditionError('A strategy already exists for this user.'));
        }

        credentials.userSalt = crypto.randomBytes(128);

        return this.getUsersRepository().create({
          kuid,
          _id: credentials.username,
          userPassword: this.passwordManager.encryptPassword(credentials.password, credentials.userSalt),
          userSalt: credentials.userSalt
        }, {refresh: 'wait_for'})
          .then(createdDocument => Promise.resolve(this.outputDocument(createdDocument)));
      });
  }

  /**
   * @param {KuzzleRequest} request
   * @param {object} credentials
   * @param {string} kuid
   * @returns {Promise<object>}
   */
  update (request, credentials, kuid) {
    if (credentials.kuid) {
      return Promise.reject(new this.context.errors.BadRequestError('The request must not contain a kuid attribute.'));
    }
    return this.getCredentialsFromUserId(kuid)
      .then(document => {
        const credentialUpdate = {};

        if (document === null) {
          return Promise.reject(new this.context.errors.PreconditionError('A strategy does not exist for this user.'));
        }

        if (credentials.password) {
          credentialUpdate.userSalt = crypto.randomBytes(128);
          credentialUpdate.userPassword = this.passwordManager.encryptPassword(credentials.password, credentialUpdate.userSalt);
        }

        // To change the username, we have to create a new (complete) document and remove the old one
        if (credentials.username && document._id !== credentials.username) {
          let createdDocument;
          const oldDocumentId = document._id;
          const newDocument = Object.assign(document, credentialUpdate);

          newDocument._id = credentials.username;
          delete newDocument.username;

          return this.getUsersRepository().create(newDocument)
            .then(create => {
              createdDocument = create;
              return this.getUsersRepository().delete(oldDocumentId);
            })
            .then(() => Promise.resolve(this.outputDocument(createdDocument)));
        }

        return this.getUsersRepository().update(Object.assign({_id: document._id}, credentialUpdate), {refresh: 'wait_for'})
          .then(() => this.getCredentialsFromUserId(kuid))
          .then(createdDocument => Promise.resolve(this.outputDocument(createdDocument)));
      });
  }

  /**
   * @param {KuzzleRequest} request
   * @param {string} kuid
   * @returns {Promise<object>}
   */
  delete (request, kuid) {
    return this.getCredentialsFromUserId(kuid)
      .then(document => {
        if (document === null) {
          return Promise.reject(new this.context.errors.PreconditionError('A strategy does not exist for this user.'));
        }

        return this.getUsersRepository().delete(document._id, {refresh: 'wait_for'});
      });
  }

  /**
   * @param {KuzzleRequest} request
   * @param {string} username
   * @returns {Promise<object>}
   */
  getById (request, username) {
    return this.getUsersRepository().get(username)
      .then(document => {
        if (document === null) {
          return Promise.reject(new this.context.errors.PreconditionError('A strategy does not exist for this username.'));
        }

        return Promise.resolve(this.outputDocument(document));
      });
  }

  /**
   * @param {KuzzleRequest} request
   * @param {string} kuid
   * @returns {Promise<object>}
   */
  getInfo (request, kuid) {
    return this.getCredentialsFromUserId(kuid)
      .then(document => {
        if (document === null) {
          return Promise.reject(new this.context.errors.PreconditionError('A strategy does not exist for this user.'));
        }

        return Promise.resolve(this.outputDocument(document));
      });
  }

  /**
   * @returns {Repository}
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
      username: user._id,
      kuid: user.kuid
    };
  }

  /**
   *
   * @param {string} kuid
   * @returns {Promise<object>}
   */
  getCredentialsFromUserId (kuid) {
    return this.getUsersRepository().search({
      query: {
        match: {
          kuid
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
