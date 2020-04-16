const
  assert = require('assert'),
  crypto = require('crypto'),
  getErrors = require('./errors'),
  getUserConstructor = require('./user'),
  jsonwebtoken = require('jsonwebtoken'),
  ms = require('ms'),
  PasswordManager = require('./passwordManager'),
  { Strategy: LocalStrategy } = require('passport-local');

/* @type AuthLocalPluginConfig */
const defaultConfig = {
  algorithm: 'sha512',
  stretching: true,
  digest: 'hex',
  encryption: 'hmac',
  passwordPolicies: [],
  requirePassword: false
};
const storageMapping = {
  config: {
    properties: {
      resetTokenSeed: {
        type: 'keyword'
      }
    }
  },
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
      },
      passwordHistory: {
        properties: {
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
          pepper: {
            type: 'boolean'
          },
          encryption: {
            type: 'keyword'
          },
          archivedAt: {
            type: 'date'
          },
          updatedAt: {
            type: 'date'
          }
        }
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
   * @property {AuthLocalPluginConfig} config
   */
  constructor () {
    this.authenticators = { LocalStrategy };
    this.context = null;
    this.passwordManager = null;
    this.strategy = null;
    this.userRepository = null;

    this.controllers = {
      password: {
        reset: request => this.resetPasswordAction(request)
      }
    };
    this.routes = [
      { action: 'reset', controller: 'password', url: '/password/reset', verb: 'post' }
    ];

    this._CONFIG_RESET_TOKEN_SEED_ID = 'resetTokenSeed';
  }

  get configRepository() {
    if (!this._configRepository) {
      this._configRepository = new this.context.constructors.Repository('config', getUserConstructor(this));
    }

    return this._configRepository;
  }

  /**
   * @param {AuthLocalPluginConfig} customConfig
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
    assert(['hash', 'hmac'].includes(this.config.encryption), 'The \'encryption\' attribute must be either \'hash\' or \'hmac\'');
    assert(!this.config.stretching || this.config.encryption !== 'hash', 'Enabling stretching with encryption \'hash\' is not possible');
    assert(typeof this.config.requirePassword === 'boolean', 'The \'requirePassword\' parameter must be set with a boolean');

    if (this.passwordManager.availableAlgorithms[this.config.algorithm] < 200) {
      this.context.log.warn('[WARNING] plugin-auth-password-local: sha1 encryption algorithm has been broken and is now deprecated. Consider using sha512 instead. Please note that changing the encryption algorithm will not invalidate existing user accounts.');
    }

    if (this.config.resetPasswordExpiresIn && this.config.resetPasswordExpiresIn !== -1) {
      let parsed = -1;
      try {
        parsed = ms(this.config.resetPasswordExpiresIn);
      }
      catch (e) {
        // will be caught be the following assert
      }
      assert(parsed > 0, `The 'resetPasswordExpiresIn' attribute must be a valid positive time representation. cf ms module documentation`);
    }
    else if (this.config.resetPasswordExpiresIn !== -1) {
      this.config.resetPasswordExpiresIn = '2h';
    }

    assert(Array.isArray(this.config.passwordPolicies), `The 'passwordPolicies' attribute must be an array`);
    for (const passwordPolicy of this.config.passwordPolicies) {
      assert(typeof passwordPolicy.appliesTo === 'object' && !Array.isArray(passwordPolicy.appliesTo) && passwordPolicy.appliesTo !== null, `The 'appliesTo' attribute of passwordPolicies elements must be an object`);
      assert(passwordPolicy.appliesTo.users || passwordPolicy.appliesTo.profiles || passwordPolicy.appliesTo.roles, `Empty 'appliesTo' attribute found for passwordPolicies. At least one of 'users', 'profiles' or 'roles' lists must be set`);

      for (const attribute of ['profiles', 'roles', 'users']) {
        assert(!passwordPolicy.appliesTo[attribute] || Array.isArray(passwordPolicy.appliesTo[attribute]), `The '${attribute}' attribute of passwordPolicies must be an array`);
      }
    }

    this.initStrategies();

    this.errors = getErrors(context.errors);

    await this.context.accessors.storage.bootstrap(storageMapping);

    if (!this.config.resetPasswordSeed) {
      let seed = crypto.randomBytes(512).toString('hex');

      try {
        await this.configRepository.create(
          this._CONFIG_RESET_TOKEN_SEED_ID,
          { seed }
        );
      }
      catch (e) {
        if (e.id && e.id === 'services.storage.document_already_exists') {
          seed = (await this.configRepository.get(this._CONFIG_RESET_TOKEN_SEED_ID)).seed;
        }
        else {
          throw e;
        }
      }

      this.config.resetPasswordSeed = seed;
    }
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
      throw new this.errors.BadRequestError('kuid cannot be specified in credentials.');
    }

    if (credentials.username) {
      const userByName = await this.getUsersRepository().get(credentials.username);
      if (userByName !== null && kuid !== userByName.kuid) {
        throw new this.errors.PreconditionError(`Login "${credentials.username}" is already used.`);
      }
    }

    if (isUpdate) {
      return this._validateUpdate(request, credentials, kuid);
    }

    return this._validateCreate(request, credentials, kuid);
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

    if (await user.isPasswordExpired()) {
      const error = new this.errors.ExpiredPasswordError();
      return {
        kuid: null,
        message: error.message,
        statusCode: error.status,
        id: error.id,
        code: error.code,
        resetToken: jsonwebtoken.sign(
          user.kuid,
          this.config.resetPasswordSeed,
          {
            expiresIn: this.config.resetPasswordExpiresIn,
            issuer: 'kuzzle-plugin-auth-passport-local'
          }
        )
      };
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
      throw new this.errors.BadRequestError('Password needed.');
    }

    const exists = await this.exists(request, kuid);

    if (exists) {
      throw new this.errors.PreconditionError(`A strategy already exists for user "${kuid}".`);
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
      throw new this.errors.BadRequestError('The request must not contain a kuid attribute.');
    }

    const user = await this.getCredentialsFromUserId(kuid);

    await this.passwordRequiredCheck(request, user);

    // must be tested after the requirePassword check: we must return a
    // "invalid user or password" message before this check in case someone
    // tries to guess if a username exists using this route
    if (user === null) {
      throw new this.errors.PreconditionError(`No credentials found for user "${kuid}".`);
    }

    const credentialUpdate = {};

    if (credentials.password) {
      credentialUpdate.userSalt = crypto.randomBytes(128).toString('hex');
      credentialUpdate.algorithm = this.config.algorithm;
      credentialUpdate.stretching = this.config.stretching;
      credentialUpdate.encryption = this.config.encryption;
      credentialUpdate.userPassword = await this.passwordManager.encryptPassword(
        credentials.password,
        credentialUpdate.userSalt);
      credentialUpdate.passwordHistory = [];

      const retention = await user.getPasswordRetention();
      if (retention) {
        const current = {
          userPassword: user.userPassword,
          userSalt: user.userSalt,
          algorithm: user.algorithm,
          stretching: user.stretching,
          pepper: user.pepper,
          encryption: user.encryption,
          archivedAt: Date.now(),
          updatedAt: user.updatedAt
        };

        credentialUpdate.passwordHistory = [current, ...(user.passwordHistory || [])]
          .slice(0, retention - 1);
      }
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
      throw new this.errors.PreconditionError(`No credentials found for user "${kuid}".`);
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
      throw new this.errors.PreconditionError(`No credentials found for username "${username}".`);
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
      throw new this.errors.PreconditionError(`No credentials found for user "${kuid}".`);
    }

    return this.outputDocument(user);
  }

  /**
   * @returns {Repository}
   */
  getUsersRepository () {
    if (!this.userRepository) {
      this.userRepository = new this.context.constructors.Repository('users', getUserConstructor(this));
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
      throw new this.errors.BadRequestError('Cannot update credentials: password required.');
    }

    if ( user === null
      || await this.passwordManager.checkPassword(password, user) === false
    ) {
      throw new this.errors.ForbiddenError('Invalid user or password.');
    }
  }

  /**
   * @param {KuzzleRequest} request
   * @returns {Promise<boolean>}
   */
  async resetPasswordAction (request) {
    if (!request.input.body) {
      throw new this.errors.BadRequestError('Missing request body');
    }

    const {
      password,
      token
    } = request.input.body;

    if (!password) {
      throw new this.errors.BadRequestError('Missing "password" attribute');
    }
    if (typeof password !== 'string' || password.trim() === '') {
      throw new this.errors.BadRequestError('Invalid password supplied. Must be a non-empty string');
    }
    if (!token) {
      throw new this.errors.BadRequestError('Missing "token" attribute');
    }
    if (typeof token !== 'string') {
      throw new this.errors.BadRequestError('Invalid token supplied');
    }

    let kuid;
    try {
      kuid = jsonwebtoken.verify(token);
    }
    catch (e) {
      if (e instanceof jsonwebtoken.TokenExpiredError) {
        throw new this.errors.ExpiredTokenError();
      }

      if (e instanceof jsonwebtoken.JsonWebTokenError) {
        throw new this.errors.InvalidTokenError(e.message);
      }

      throw new this.errors.BadRequestError(e.message);
    }

    await this.validate(request, {password}, kuid, 'local', true);
    await this.update(request, {password}, kuid);

    const loginRequest = new this.context.constructors.Request({
      action: 'login',
      body: {
        password,
        username: kuid
      },
      controller: 'auth',
      strategy: 'local'
    }, request.context);
    const loginResponse = await this.context.accessors.execute(loginRequest);

    return loginResponse.result;
  }

  /**
   * @param {KuzzleRequest} request
   * @param {{ username: string, password: string }} credentials
   * @param {string} kuid
   * @returns {Promise<boolean>}
   */
  async _validateCreate(request, credentials, kuid) {
    if (!credentials.username) {
      throw new this.errors.BadRequestError('Username required.');
    }

    if (!credentials.password) {
      throw new this.errors.BadRequestError('Password required.');
    }

    const user = await this.getUsersRepository().get(credentials.username);

    if (user !== null && kuid !== user.kuid) {
      throw new this.errors.PreconditionError(`Login "${credentials.username}" is already used.`);
    }

    return true;
  }

  /**
   * @param {KuzzleRequest} request
   * @param {{ username: string, password: string }} credentials
   * @paral {string} kuid
   * @returns {Promise<boolean>}
   */
  async _validateUpdate(request, credentials, kuid) {
    if (!credentials.username && !credentials.password) {
      throw new this.errors.BadRequestError('Missing username or password.');
    }

    const user = await this.getUsersRepository().get(kuid);
    return user.validateUpdate(request, credentials);
  }
}

module.exports = AuthenticationPlugin;
