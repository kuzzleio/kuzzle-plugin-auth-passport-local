const assert = require('assert');
const crypto = require('crypto');
const debug = require('debug')('kuzzle-plugin-auth-passport-local');
const getUserConstructor = require('./getUserConstructor');
const jsonwebtoken = require('jsonwebtoken');
const ms = require('ms');
const PasswordManager = require('./passwordManager');
const { Strategy: LocalStrategy } = require('passport-local');

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
      resetTokenSecret: {
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
      // we need to store the updater manually
      updater: {
        type: 'keyword'
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

    this.api = {
      password: {
        actions: {
          getResetPasswordToken: {
            handler: this.getResetPasswordTokenAction,
            http: [ { verb: 'get', path: '/password/resetToken/:_id' } ],
          },
          reset: {
            handler: this.resetPasswordAction,
            http: [ { verb: 'post', path: '/password/reset' } ],
          }
        }
      }
    };

    this._CONFIG_RESET_TOKEN_SECRET_ID = 'resetTokenSecret';

    this.User = getUserConstructor(this);
  }

  get configRepository() {
    if (!this._configRepository) {
      this._configRepository = new this.context.constructors.Repository('config');
    }

    return this._configRepository;
  }

  /**
   * @param {AuthLocalPluginConfig} customConfig
   * @param {KuzzlePluginContext} context
   * @returns {Promise<*>}
   */
  async init (customConfig, context) {
    this.config = Object.assign({}, defaultConfig, customConfig);
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
        parsed = ms(`${this.config.resetPasswordExpiresIn}`);
      }
      catch (e) {
        // will be caught be the following assert
      }
      assert(parsed > 0, `The 'resetPasswordExpiresIn' attribute must be a valid positive time representation. cf ms module documentation`);
      this.config.resetPasswordExpiresIn = parsed;
    }
    else if (this.config.resetPasswordExpiresIn !== -1) {
      this.config.resetPasswordExpiresIn = ms('2h');
    }

    assert(Array.isArray(this.config.passwordPolicies), `The 'passwordPolicies' attribute must be an array`);
    for (const passwordPolicy of this.config.passwordPolicies) {
      assert(
        (
          typeof passwordPolicy.appliesTo === 'string'
          && passwordPolicy.appliesTo === '*'
        )
        ||
        (
          typeof passwordPolicy.appliesTo === 'object'
          && !Array.isArray(passwordPolicy.appliesTo)
          && passwordPolicy.appliesTo !== null
        ),
        `The 'appliesTo' attribute of passwordPolicies elements must either be equal to '*' or be an object`
      );
      if (typeof passwordPolicy.appliesTo === 'object') {
        assert(passwordPolicy.appliesTo.users || passwordPolicy.appliesTo.profiles || passwordPolicy.appliesTo.roles, `Empty 'appliesTo' attribute found for passwordPolicies. At least one of 'users', 'profiles' or 'roles' lists must be set`);

        for (const attribute of ['profiles', 'roles', 'users']) {
          assert(!passwordPolicy.appliesTo[attribute] || Array.isArray(passwordPolicy.appliesTo[attribute]), `The '${attribute}' attribute of passwordPolicies must be an array`);
        }
      }
      if (passwordPolicy.expiresAfter) {
        let parsed = -1;
        try {
          parsed = ms(`${passwordPolicy.expiresAfter}`);
        }
        catch (e) {
          // will be caught by the next assertion
        }
        assert(parsed > 0, `The 'expiresAfter' attribute must be a valid positive time representation. cf ms module documentation`);
      }
    }

    this.initStrategies();

    await this.context.accessors.storage.bootstrap(storageMapping);

    // secret cannot be set via config
    {
      let secret = crypto.randomBytes(512).toString('hex');

      try {
        await this.configRepository.create({
          _id: this._CONFIG_RESET_TOKEN_SECRET_ID,
          secret: secret
        });
      }
      catch (e) {
        if (e.id && e.id === 'services.storage.document_already_exists') {
          secret = (await this.configRepository.get(this._CONFIG_RESET_TOKEN_SECRET_ID)).secret;
        }
        else {
          throw e;
        }
      }

      this.config.resetPasswordSecret = secret;
    }

    debug('computed config: %O', Object.assign({}, this.config, {resetPasswordSecret: '**secret**'}));
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
    debug('validate(kuid = %s, isUpdate = %s)', kuid, isUpdate);

    if (credentials.kuid) {
      throw new this.context.errors.BadRequestError('kuid cannot be specified in credentials.');
    }

    if (credentials.username) {
      const userByName = await this.getUsersRepository().get(credentials.username);
      if (userByName !== null && kuid !== userByName.kuid) {
        throw new this.context.errors.PreconditionError(`Login "${credentials.username}" is already used.`);
      }
    }

    if (isUpdate) {
      return this._validateUpdate(credentials, kuid);
    }

    return this._validateCreate(credentials, kuid);
  }

  /**
   * @param {KuzzleRequest} request
   * @param {string} kuid
   * @returns {Promise<boolean>}
   */
  async exists (request, kuid) {
    debug('exists(kuid = %s)', kuid);

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
    debug('verify(username = %s)', username);

    const user = await this.getUsersRepository().get(username);

    const equal = user !== null
      && await this.passwordManager.checkPassword(password, user);

    if (!equal) {
      return {kuid: null, message: 'wrong username or password'};
    }

    const isPasswordExpired = await user.isPasswordExpired();
    const passwordMustBeChanged = await user.passwordMustBeChanged();

    if (isPasswordExpired || passwordMustBeChanged) {
      const error = isPasswordExpired
        ? this.context.errorsManager.get('expired_password')
        : this.context.errorsManager.get('must_change_password');

      error.resetToken = this._getResetPasswordToken(user.kuid);
      throw error;
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
      encryption: this.config.encryption,
      updater: request.context.user && request.context.user._id
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

    if (credentials.password) {
      credentialUpdate.userSalt = crypto.randomBytes(128).toString('hex');
      credentialUpdate.algorithm = this.config.algorithm;
      credentialUpdate.stretching = this.config.stretching;
      credentialUpdate.encryption = this.config.encryption;
      credentialUpdate.userPassword = await this.passwordManager.encryptPassword(
        credentials.password,
        credentialUpdate.userSalt);
      credentialUpdate.updater = request.context.user && request.context.user._id;
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
          updatedAt: user._kuzzle_info.updatedAt
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
      this.userRepository = new this.context.constructors.Repository('users', this.User);
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
    if ( !this.config.requirePassword || request.input.controller !== 'auth') {
      return;
    }

    let password = null;

    if (request.input.body && request.input.body.currentPassword) {
      password = request.input.body.currentPassword;
    }
    // @deprecated (and undocumented) - compatibility with 6.1 only, should not
    //                                  be used because HTTP querystrings are
    //                                  written in logs
    else {
      password = request.input.args.password;
    }

    if (typeof password !== 'string' || password.length === 0) {
      throw new this.context.errors.BadRequestError('Cannot update credentials: password required.');
    }

    const isValid = await this.passwordManager.checkPassword(password, user);

    if (user === null || isValid === false) {
      throw new this.context.errors.ForbiddenError('Invalid user or password.');
    }
  }

  // controller actions
  // --------------------------------------------------------------------------
  /**
   * @param {KuzzleRequest} request
   * @returns {Promise<string>}
   */
  async getResetPasswordTokenAction (request) {
    const { _id: kuid } = request.input.resource;

    if (!kuid) {
      throw new this.context.errors.BadRequestError('Missing kuid');
    }
    // type checking is alredy done at Request level

    const user = await this.getCredentialsFromUserId(kuid);
    if (!user) {
      throw new this.context.errors.BadRequestError('Invalid kuid given');
    }

    return {
      resetToken: this._getResetPasswordToken(kuid)
    };
  }

  /**
   * @param {KuzzleRequest} request
   * @returns {Promise<boolean>}
   */
  async resetPasswordAction (request) {
    if (!request.input.body) {
      throw new this.context.errors.BadRequestError('Missing request body');
    }

    const {
      password,
      token
    } = request.input.body;

    if (!password) {
      throw new this.context.errors.BadRequestError('Missing "password" attribute');
    }
    if (typeof password !== 'string' || password.trim() === '') {
      throw new this.context.errors.BadRequestError('Invalid password supplied. Must be a non-empty string');
    }
    if (!token) {
      throw new this.context.errors.BadRequestError('Missing "token" attribute');
    }
    if (typeof token !== 'string') {
      throw new this.context.errors.BadRequestError('Invalid token supplied');
    }

    let kuid;
    try {
      kuid = jsonwebtoken.verify(token, this.config.resetPasswordSecret).resetForKuid;
    }
    catch (e) {
      if (e instanceof jsonwebtoken.TokenExpiredError) {
        throw this.context.errorsManager.get('expired_token');
      }

      if (e instanceof jsonwebtoken.JsonWebTokenError) {
        throw this.context.errorsManager.get('invalid_token');
      }

      throw new this.context.errors.BadRequestError(e.message);
    }

    await this.validate(request, {password}, kuid, 'local', true);
    await this.update(request, {password}, kuid);

    const user = await this.getCredentialsFromUserId(kuid);

    const loginRequest = new this.context.constructors.Request({
      action: 'login',
      body: {
        password,
        username: user._id
      },
      controller: 'auth',
      strategy: 'local'
    }, request.context);
    const loginResponse = await this.context.accessors.execute(loginRequest);

    return loginResponse.result;
  }

  // private
  // --------------------------------------------------------------------------
  _getResetPasswordToken(kuid) {
    const options = {
      issuer: 'kuzzle-plugin-auth-passport-local'
    };

    if (this.config.resetPasswordExpiresIn > -1) {
      options.expiresIn = this.config.resetPasswordExpiresIn;
    }

    return jsonwebtoken.sign(
      { resetForKuid: kuid },
      this.config.resetPasswordSecret,
      options
    );
  }

  /**
   * @param {{ username: string, password: string }} credentials
   * @param {string} kuid
   * @returns {Promise<boolean>}
   */
  async _validateCreate(credentials, kuid) {
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

    const newUser = new this.User();
    newUser.kuid = kuid;

    await newUser.validateCredentials(credentials);

    return true;
  }

  /**
   * @param {{ username: string, password: string }} credentials
   * @paral {string} kuid
   * @returns {Promise<boolean>}
   */
  async _validateUpdate(credentials, kuid) {
    if (!credentials.username && !credentials.password) {
      throw new this.context.errors.BadRequestError('Missing username or password.');
    }

    const user = await this.getCredentialsFromUserId(kuid);
    return user.validateCredentials(credentials);
  }
}

module.exports = AuthenticationPlugin;
