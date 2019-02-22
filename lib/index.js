const
  crypto = require('crypto'),
  semver = require('semver'),
  PasswordManager = require('./passwordManager'),
  LocalStrategy = require('passport-local').Strategy,
  defaultConfig = {
    algorithm: 'sha512',
    stretching: true,
    digest: 'hex',
    encryption: 'hmac'
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
        },
        algorithm: {
          type: 'keyword'
        },
        stretching: {
          type: 'boolean'
        },
        // For future uses: tells if a pepper has been
        // used to encrypt this password
        pepper: {
          type: 'boolean'
        },
        encryption: {
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
    // to be used with Kuzzle post-1.4.0
    this.authenticators = {LocalStrategy};
  }

  /**
   * @param {object} customConfig
   * @param {KuzzlePluginContext} context
   * @returns {Promise<*>}
   */
  init (customConfig, context) {
    this.config = Object.assign(defaultConfig, customConfig);
    this.context = context;
    this.passwordManager = new PasswordManager(this.config, this.context);

    if (!this.config.algorithm) {
      return Promise.reject(new this.context.errors.PluginImplementationError('plugin-auth-passport-local: The \'algorithm\' attribute is required'));
    }

    if (!this.passwordManager.availableAlgorithms[this.config.algorithm]) {
      return Promise.reject(new this.context.errors.PluginImplementationError(`plugin-auth-passport-local: The 'algorithm' attribute must be a valid algorithm; provided "${this.config.algorithm}".`));
    }

    if (this.passwordManager.availableAlgorithms[this.config.algorithm] < 200) {
      console.warn('[WARNING] plugin-auth-passwort-local: sha1 encryption algorithm has been broken and is now deprecated. Consider using sha512 instead. Please note that changing the encryption algorithm will not invalidate existing user accounts.');
    }

    if (!this.config.digest) {
      return Promise.reject(new this.context.errors.PluginImplementationError('plugin-auth-passport-local: The \'digest\' attribute is required'));
    }

    if (['hash', 'hmac'].indexOf(this.config.encryption) === -1) {
      return Promise.reject(new this.context.errors.PluginImplementationError('plugin-auth-passport-local: The \'encryption\' attribute must be either \'hash\' or \'hmac\''));
    }

    if (this.config.stretching && this.config.encryption === 'hash') {
      return Promise.reject(new this.context.errors.PluginImplementationError('plugin-auth-passport-local: Enabling stretching with encryption \'hash\' is not possible'));
    }

    this.initStrategies();

    return this.context.accessors.storage.bootstrap(storageMapping)
      .then(() => true);
  }

  initStrategies () {
    this.strategies = {
      local: {
        config: {
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

    // This snippet simply suppresses a warning emitted by Kuzzle during
    // plugin initialization.
    // See https://github.com/kuzzleio/kuzzle/pull/1145
    if (semver.lt(this.context.config.version, '1.4.0')) {
      this.strategies.local.config.constructor = LocalStrategy;
    } else {
      this.strategies.local.config.authenticator = 'LocalStrategy';
    }
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
    let user;

    return this.getUsersRepository().get(username)
      .then(result => {
        if (result === null) {
          // no user found: directly return a password check fail
          return false;
        }

        user = result;

        return this.passwordManager.checkPassword(password, user);
      })
      .then(equal => {
        if (!equal) {
          return Promise.resolve({
            kuid: null,
            message: 'wrong username or password'
          });
        }

        if (user.algorithm !== this.config.algorithm || user.stretching !== this.config.stretching || user.encryption !== this.config.encryption) {
          return this.update(request, {password}, user.kuid)
            .then(() => ({kuid: user.kuid}))
            .catch(() => ({kuid: user.kuid}));
        }

        return {kuid: user.kuid};
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
          throw new this.context.errors.PreconditionError(`A strategy already exists for user "${kuid}".`);
        }

        credentials.userSalt = crypto.randomBytes(128).toString('hex');

        return this.passwordManager.encryptPassword(credentials.password, credentials.userSalt);
      })
      .then(encrypted => {
        return this.getUsersRepository().create({
          kuid,
          _id: credentials.username,
          userPassword: encrypted,
          userSalt: credentials.userSalt,
          algorithm: this.config.algorithm,
          stretching: this.config.stretching,
          pepper: false, // for future uses
          encryption: this.config.encryption
        }, {refresh: 'wait_for'});
      })
      .then(createdDocument => this.outputDocument(createdDocument));
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

    const credentialUpdate = {};
    let chainStart;

    if (credentials.password) {
      credentialUpdate.userSalt = crypto.randomBytes(128).toString('hex');
      credentialUpdate.algorithm = this.config.algorithm;
      credentialUpdate.stretching = this.config.stretching;
      credentialUpdate.encryption = this.config.encryption;
      chainStart = this.passwordManager.encryptPassword(credentials.password, credentialUpdate.userSalt);
    }
    else {
      chainStart = Promise.resolve(null);
    }

    return chainStart
      .then(encrypted => {
        if (encrypted !== null) {
          credentialUpdate.userPassword = encrypted;
        }

        return this.getCredentialsFromUserId(kuid);
      })
      .then(document => {
        if (document === null) {
          throw new this.context.errors.PreconditionError(`A strategy does not exist for user "${kuid}".`);
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
            .then(() => this.outputDocument(createdDocument));
        }

        return this.getUsersRepository().update(Object.assign({_id: document._id}, credentialUpdate), {refresh: 'wait_for'})
          .then(() => this.getCredentialsFromUserId(kuid))
          .then(createdDocument => this.outputDocument(createdDocument));
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
          throw new this.context.errors.PreconditionError(`A strategy does not exist for user "${kuid}".`);
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
          throw new this.context.errors.PreconditionError(`A strategy does not exist for username "${username}".`);
        }

        return this.outputDocument(document);
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
          throw new this.context.errors.PreconditionError(`A strategy does not exist for user "${kuid}".`);
        }

        return this.outputDocument(document);
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
          return null;
        }

        return result.hits[0];
      });
  }
}

module.exports = AuthenticationPlugin;
