const
  assert = require('assert'),
  crypto = require('crypto'),
  PasswordManager = require('./passwordManager'),
  { Strategy: LocalStrategy } = require('passport-local');

const
  defaultConfig = {
    algorithm: 'sha512',
    stretching: true,
    digest: 'hex',
    encryption: 'hmac',
    requirePassword: false
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
    this.authenticators = { LocalStrategy };
  }

  /**
   * @param {object} customConfig
   * @param {KuzzlePluginContext} context
   * @returns {Promise<*>}
   */
  async init (customConfig, context) {
    this.config = Object.assign(defaultConfig, customConfig);
    this.context = context;
    this.passwordManager = new PasswordManager(this.config, this.context);

    assert(typeof this.config.algorithm === 'string', 'The \'algorithm\' attribute is required');
    assert(this.passwordManager.availableAlgorithms[this.config.algorithm], `The 'algorithm' attribute must be a valid algorithm; provided "${this.config.algorithm}".`);
    assert(typeof this.config.digest === 'string', 'The \'digest\' attribute is required');
    assert(['hash', 'hmac'].indexOf(this.config.encryption) !== -1, 'The \'encryption\' attribute must be either \'hash\' or \'hmac\'');
    assert(!this.config.stretching || this.config.encryption !== 'hash', 'Enabling stretching with encryption \'hash\' is not possible');
    assert(typeof this.config.requirePassword === 'boolean', 'The \'requirePassword\' parameter must be set with a boolean');

    if (this.passwordManager.availableAlgorithms[this.config.algorithm] < 200) {
      this.context.log.warn('[WARNING] plugin-auth-passwort-local: sha1 encryption algorithm has been broken and is now deprecated. Consider using sha512 instead. Please note that changing the encryption algorithm will not invalidate existing user accounts.');
    }

    this.initStrategies();

    return this.context.accessors.storage.bootstrap(storageMapping);
  }

  initStrategies () {
    this.strategies = {
      local: {
        config: {
          authenticator: 'LocalStrategy',
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
  async validate (request, credentials, kuid, strategy, isUpdate) {
    if (credentials.kuid) {
      throw new this.context.errors.BadRequestError('kuid cannot be specified in credentials.');
    }

    if (isUpdate) {
      if (!credentials.username && !credentials.password) {
        throw new this.context.errors.BadRequestError('Missing username or password.');
      }

      return true;
    }

    if (!credentials.username) {
      throw new this.context.errors.BadRequestError('Username required.');
    }

    if (!credentials.password) {
      throw new this.context.errors.BadRequestError('Password required.');
    }

    const user = await this.getUsersRepository().get(credentials.username);

    if (user !== null && kuid !== user.kuid) {
      throw new this.context.errors.PreconditionError(`Login "${credentials.username}" is already used.`);
    }

    return true;
  }

  /**
   * @param {KuzzleRequest} request
   * @param {string} kuid
   * @returns {Promise<boolean>}
   */
  async exists (request, kuid) {
    const credentials = await this.getCredentialsFromUserId(kuid);

    return credentials !== null;
  }

  /**
   * @param {KuzzleRequest} request
   * @param {string} username
   * @param {string} password
   * @returns {Promise<string|{message: string}>}
   */
  async verify (request, username, password) {
    const user = await this.getUsersRepository().get(username);

    const equal = user !== null
      && await this.passwordManager.checkPassword(password, user);

    if (!equal) {
      return {kuid: null, message: 'wrong username or password'};
    }

    if ( user.algorithm !== this.config.algorithm
      || user.stretching !== this.config.stretching
      || user.encryption !== this.config.encryption
    ) {
      try {
        await this.update(request, {password}, user.kuid);
      }
      catch (e) {
        // ignore any silent migration error
      }
    }

    return {kuid: user.kuid};
  }

  /**
   * @param {KuzzleRequest} request
   * @param {object} credentials
   * @param {string} kuid
   * @returns {Promise<object>}
   */
  async create (request, credentials, kuid) {
    if (!credentials.password) {
      throw new this.context.errors.BadRequestError('Password needed.');
    }

    const exists = await this.exists(request, kuid);

    if (exists) {
      throw new this.context.errors.PreconditionError(`A strategy already exists for user "${kuid}".`);
    }

    credentials.userSalt = crypto.randomBytes(128).toString('hex');

    const encrypted = await this.passwordManager.encryptPassword(
      credentials.password,
      credentials.userSalt);

    const created = await this.getUsersRepository().create({
      kuid,
      _id: credentials.username,
      userPassword: encrypted,
      userSalt: credentials.userSalt,
      algorithm: this.config.algorithm,
      stretching: this.config.stretching,
      pepper: false, // for future uses
      encryption: this.config.encryption
    }, {refresh: 'wait_for'});

    return this.outputDocument(created);
  }

  /**
   * @param {KuzzleRequest} request
   * @param {object} credentials
   * @param {string} kuid
   * @returns {Promise<object>}
   */
  async update (request, credentials, kuid) {
    if (credentials.kuid) {
      throw new this.context.errors.BadRequestError('The request must not contain a kuid attribute.');
    }

    const user = await this.getCredentialsFromUserId(kuid);

    await this.passwordRequiredCheck(request, user);

    // must be tested after the requirePassword check: we must return a
    // "invalid user or password" message before this check in case someone
    // tries to guess if a username exists using this route
    if (user === null) {
      throw new this.context.errors.PreconditionError(`No credentials found for user "${kuid}".`);
    }

    const credentialUpdate = {};
    let encrypted = null;

    if (credentials.password) {
      credentialUpdate.userSalt = crypto.randomBytes(128).toString('hex');
      credentialUpdate.algorithm = this.config.algorithm;
      credentialUpdate.stretching = this.config.stretching;
      credentialUpdate.encryption = this.config.encryption;
      encrypted = await this.passwordManager.encryptPassword(
        credentials.password,
        credentialUpdate.userSalt);
    }

    if (encrypted !== null) {
      credentialUpdate.userPassword = encrypted;
    }


    let updated;

    // To change the username, we have to create a new (complete) document and
    // remove the old one
    if (credentials.username && user._id !== credentials.username) {
      const
        oldDocumentId = user._id,
        newDocument = Object.assign({}, user, credentialUpdate);

      newDocument._id = credentials.username;
      delete newDocument.username;

      updated = await this.getUsersRepository().create(newDocument);
      await this.getUsersRepository().delete(oldDocumentId);
    }
    else {
      await this.getUsersRepository().update(
        Object.assign({_id: user._id}, credentialUpdate),
        {refresh: 'wait_for'});

      updated = await this.getCredentialsFromUserId(kuid);
    }

    return this.outputDocument(updated);
  }

  /**
   * @param {KuzzleRequest} request
   * @param {string} kuid
   * @returns {Promise<object>}
   */
  async delete (request, kuid) {
    const user = await this.getCredentialsFromUserId(kuid);

    await this.passwordRequiredCheck(request, user);

    if (user === null) {
      throw new this.context.errors.PreconditionError(`No credentials found for user "${kuid}".`);
    }

    return this.getUsersRepository().delete(user._id, {refresh: 'wait_for'});
  }

  /**
   * @param {KuzzleRequest} request
   * @param {string} username
   * @returns {Promise<object>}
   */
  async getById (request, username) {
    const user = await this.getUsersRepository().get(username);

    if (user === null) {
      throw new this.context.errors.PreconditionError(`No credentials found for username "${username}".`);
    }

    return this.outputDocument(user);
  }

  /**
   * @param {KuzzleRequest} request
   * @param {string} kuid
   * @returns {Promise<object>}
   */
  async getInfo (request, kuid) {
    const user = await this.getCredentialsFromUserId(kuid);

    if (user === null) {
      throw new this.context.errors.PreconditionError(`No credentials found for user "${kuid}".`);
    }

    return this.outputDocument(user);
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
  async getCredentialsFromUserId (kuid) {
    const result = await this.getUsersRepository().search({
      query: {
        match: {
          kuid
        }
      }
    });

    if (result.total === 0) {
      return null;
    }

    return result.hits[0];
  }

  /**
   * Enforces required password restrictions
   * @param  {Request} request
   * @param  {Object} user
   */
  async passwordRequiredCheck (request, user) {
    if ( !this.config.requirePassword
      || request.input.controller === 'security'
    ) {
      return;
    }

    const password = request.input.args.password;

    if (typeof password !== 'string' || password.length === 0) {
      throw new this.context.errors.BadRequestError('Cannot update credentials: password required.');
    }

    if ( user === null
      || await this.passwordManager.checkPassword(password, user) === false
    ) {
      throw new this.context.errors.ForbiddenError('Invalid user or password.');
    }
  }
}

module.exports = AuthenticationPlugin;
