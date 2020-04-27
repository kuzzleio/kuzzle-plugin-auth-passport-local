const
  should = require('should'),
  PluginLocal = require('../lib'),
  PluginContext = require('./mock/pluginContext.mock.js');

describe('#user', () => {
  let
    pluginLocal,
    pluginContext,
    user;

  beforeEach(async () => {
    pluginContext = new PluginContext();
    pluginLocal = new PluginLocal();
    await pluginLocal.init({}, pluginContext);
    pluginLocal.userRepository = new (require('./mock/getUserRepository.mock')(pluginLocal))();

    user = await pluginLocal.userRepository.get('foo');
  });

  describe('#getKuzzleUser', () => {
    it('should return a kuzzle user from the sdk', async () => {
      const kuzzleUser = await user.getKuzzleUser();

      should(kuzzleUser).eql(
        await pluginContext.accessors.sdk.security.getUser.firstCall.returnValue
      );

      should(kuzzleUser).eql({
        _id: 'foo',
        content: {
          profileIds: [
            'profile1',
            'profile2'
          ]
        }
      });
    });
  });

  describe('#getKuzzleUserProfiles', () => {
    it('should return user profiles', async () => {
      const profiles = await user.getKuzzleUserProfiles();

      should(profiles).eql(
        await pluginContext.accessors.sdk.security.mGetProfiles.firstCall.returnValue
      );
    });
  });

  describe('#getPasswordRetention', () => {
    it('returns 0 if no retention is set', async () => {
      should(await user.getPasswordRetention()).eql(0);
    });

    it('should return the max of defined retention periods', async () => {
      pluginLocal.config.passwordPolicies = [
        {
          appliesTo: '*',
          forbidReusedPasswordCount: 2
        },
        {
          appliesTo: {
            users: 'foo'
          },
          forbidReusedPasswordCount: 42
        }
      ];

      should(await user.getPasswordRetention()).eql(42);
    });
  });

  describe('#getPolicies', () => {
    it('should filter policies according to user profiles', async () => {
      pluginLocal.config.passwordPolicies = [
        {
          appliesTo: '*',
          id: 1
        },
        {
          appliesTo: {
            users: [
              'other',
              'foo'
            ]
          },
          id: 2
        },
        {
          appliesTo: {
            profiles: [
              'nope'
            ]
          },
          id: 3
        },
        {
          appliesTo: {
            profiles: [
              'profile2',
              'wont match'
            ]
          },
          id: 4
        },
        {
          appliesTo: {
            roles: [
              'wont either'
            ]
          },
          id: 5
        },
        {
          appliesTo: {
            roles: [
              'nope',
              'role for profile1'
            ]
          },
          id: 6
        }
      ];

      const policies = await user.getPolicies();

      should(policies.map(policy => policy.id)).eql([
        1, 2, 4, 6
      ]);
    });
  });

  describe('#isPasswordExpired', () => {
    it('should return false is no matching policy is attached to the user', async () => {
      should(await user.isPasswordExpired()).be.false();
    });

    it('should return false if the password is not expired', async () => {
      user._kuzzle_info.updatedAt = Date.now() - 1000 * 42; // 42s

      pluginLocal.config.passwordPolicies = [
        {
          appliesTo: {users: ['foo']},
          expiresAfter: '1m'
        },
        {
          appliesTo: '*',
          expiresAfter: '30m'
        }
      ];

      should(await user.isPasswordExpired()).be.false();
    });

    it('should return true if the password is expired', async () => {
      user._kuzzle_info.updatedAt = Date.now() - 1000 * 60* 42; // 42m

      pluginLocal.config.passwordPolicies = [
        {
          appliesTo: {users: ['foo']},
          expiresAfter: '1h'
        },
        {
          appliesTo: '*',
          expiresAfter: '30m'
        }
      ];

      should(await user.isPasswordExpired()).be.true();
    });
  });

  describe('#passwordMustBeChanged', () => {
    it('should return false if no policy matches', async () => {
      should(await user.passwordMustBeChanged()).be.false();
    });

    it('should return true if one policy matches', async () => {
      pluginLocal.config.passwordPolicies = [
        {
          appliesTo: {profiles: ['profile2']},
          mustChangePasswordIfSetByAdmin: true
        }
      ];

      should(await user.passwordMustBeChanged()).be.true();
    });
  });

  /*
    user.validateCredentials is tested in validate.test.js
   */
});

