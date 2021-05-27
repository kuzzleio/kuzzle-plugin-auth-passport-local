const should = require('should');
const PluginLocal = require('../lib');
const PluginContext = require('./mock/pluginContext.mock.js');
const { KuzzleRequest } = require('kuzzle');

describe('#validate', () => {
  const pluginContext = new PluginContext();
  let
    pluginLocal,
    request;

  beforeEach(async () => {
    pluginLocal = new PluginLocal();
    await pluginLocal.init({}, pluginContext);
    pluginLocal.userRepository = new (require('./mock/getUserRepository.mock')(pluginLocal))();

    request = new KuzzleRequest({});
  });

  it('should throw an error if the credentials are not well-formed', () => {
    return should(pluginLocal.validate(request, {}, 'foo', false))
      .be.rejectedWith('Username required.');
  });

  it('should throw an error if the kuid is provided in the credentials', () => {
    return should(pluginLocal.validate(request, {kuid: 'foo', username: 'bar'}, 'foo'))
      .be.rejectedWith('kuid cannot be specified in credentials.');
  });

  it('should return true if the provided username equals the kuid', async () => {
    const response = await pluginLocal.validate(
      request,
      {username: 'foo', password: 'bar'},
      'foo'
    );

    should(response).be.true();
  });

  it('should return true if no user was found for the given kuid', () => {
    return should(pluginLocal.validate(null, {username:'ghost', password:'bar'}, 'foo')).be.fulfilledWith(true);
  });

  it('should throw an error if the provided username differs from the kuid', () => {
    return should(pluginLocal.validate(null, {username: 'bar', password: 'bar'}, 'foo')).be.rejectedWith('Login "bar" is already used.');
  });

  describe('#policies - forbid login in password', () => {
    beforeEach(() => {
      pluginLocal.config.passwordPolicies = [
        {
          appliesTo: '*',
          forbidLoginInPassword: true
        }
      ];
    });

    it('should allow user creation if password does not contain login', async () => {
      pluginLocal.userRepository.get = async () => null;
      pluginLocal.userRepository.search.resolves({
        total: 0,
        hits: []
      });

      const response = await pluginLocal.validate(
        request,
        {
          username: 'login',
          password: 'something else'
        },
        'kuid',
        'local',
        false
      );

      should(response).be.true();
    });

    it('should throw on creation if the password contains the login', () => {
      pluginLocal.userRepository.get = async () => null;
      pluginLocal.userRepository.search.resolves({
        total: 0,
        hits: []
      });

      const err = pluginContext.errorsManager.get('login_in_password');

      return should(pluginLocal.validate(
        request,
        {
          username: 'lOGin',
          password: 'fooLoGInbar'
        },
        'kuid',
        'local',
        false
      ))
        .be.rejectedWith(err);
    });

    it('should allow update if the password does not contain the login', async () => {
      const response = await pluginLocal.validate(
        request,
        {password: 'not the key for bar'},
        'kuid',
        'local',
        true
      );

      should(response).be.true();
    });

    it('should throw on update if the password contains the login', () => {
      const err = pluginContext.errorsManager.get('login_in_password');

      return should(pluginLocal.validate(
        request,
        {password: 'FoO2 is not allowed'},
        'kuid',
        'local',
        true
      ))
        .be.rejectedWith(err);
    });
  });

  describe('#policies - forbid reuse', () => {
    beforeEach(async () => {
      pluginLocal.config.passwordPolicies = [
        {
          appliesTo: '*',
          forbidReusedPasswordCount: 5
        }
      ];

      const passwordHistory = [];
      for (let i = 0; i < 8; i++) {
        const password = `password${i}`;

        passwordHistory.push({
          algorithm: pluginLocal.config.algorithm,
          encryption: pluginLocal.config.encryption,
          pepper: false,
          stretching: pluginLocal.config.stretching,
          userPassword: await pluginLocal.passwordManager.encryptPassword(password, 'salt' + password),
          userSalt: 'salt' + password
        });
      }

      pluginLocal.userRepository.search.returns({
        total: 1,
        hits: [
          pluginLocal.userRepository.fromDTO({
            passwordHistory,
            _id: 'username',
            algorithm: pluginLocal.config.algorithm,
            encryption: pluginLocal.config.encryption,
            kuid: 'kuid',
            pepper: false,
            stretching: pluginLocal.config.stretching,
            userPassword: await pluginLocal.passwordManager.encryptPassword('password', 'salt'),
            userSalt: 'salt',
            _kuzzle_info: {
              author: null,
              createdAt: Date.now() - 1000 * 3600 * 24 * 30,
              updatedAt: Date.now() - 1000 * 3600 * 24 * 15,
              updater: 'kuid'
            }
          })
        ]
      });
    });

    it('should allow setting a password that is not in the history', async () => {
      const response = await pluginLocal.validate(
        request,
        {password: 'something new'},
        'kuid',
        'local',
        true
      );

      should(response).be.true();
    });

    it('should allow to reuse a password that is after the count limit', async () => {
      const response = await pluginLocal.validate(
        request,
        {password: 'password7'},
        'kuid',
        'local',
        true
      );

      should(response).be.true();
    });

    it('should throw if a password is reused', () => {
      const err = pluginContext.errorsManager.get('reused_password');

      return should(pluginLocal.validate(
        request,
        {password: 'password3'},
        'kuid',
        'local',
        true
      ))
        .be.rejectedWith(err);
    });
  });

  describe('#policies - password regex', () => {
    beforeEach(() => {
      pluginLocal.config.passwordPolicies = [
        {
          appliesTo: '*',
          passwordRegex: '(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*\\W){8,}' // is set from config => always a string
        }
      ];
    });

    it('should allow passwords which match', async () => {
      const response = await pluginLocal.validate(
        request,
        {password: 'aB0%aB0%'},
        'kuid',
        'local',
        true
      );

      should(response).be.true();
    });

    it('should throw if the password does not match', () => {
      const err = pluginContext.errorsManager.get('weak_password');

      return should(pluginLocal.validate(
        request,
        {password: 'does not match regex'},
        'kuid',
        'local',
        true
      ))
        .be.rejectedWith(err);
    });

    it('should handle escaped regexes', async () => {
      pluginLocal.config.passwordPolicies = [
        {
          appliesTo: '*',
          passwordRegex: '/http:\\/\\/www\\.example\\.com/i'
        }
      ];

      const response = await pluginLocal.validate(
        request,
        {password: 'HTTP://www.exaMPLE.COM'},
        'kuid',
        'local',
        true
      );

      should(response).be.true();
    });
  });
});
