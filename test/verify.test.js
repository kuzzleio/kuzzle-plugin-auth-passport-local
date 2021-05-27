const should = require('should');
const sinon = require('sinon');
const jsonwebtoken = require('jsonwebtoken');
const PluginLocal = require('../lib');
const PluginContext = require('./mock/pluginContext.mock.js');
const { KuzzleRequest } = require('kuzzle');

describe('#verify', () => {
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

  it('should return the username if the credentials are valid', async () => {
    pluginLocal.update = sinon.stub().resolves();

    let response = await pluginLocal.verify(request, 'foo', 'bar');
    should(response).eql({kuid: 'foo'});
    should(pluginLocal.update).not.be.called();

    response = await pluginLocal.verify(request, 'nostretching', 'password');
    should(response).eql({kuid: 'nostretching'});
    should(pluginLocal.update)
      .be.calledWith(
        request,
        {password: 'password'},
        'nostretching'
      );

    response = await pluginLocal.verify(request, 'withHash', 'hashed');
    should(response).eql({kuid: 'withHash'});
    should(pluginLocal.update)
      .be.calledWith(
        request,
        {password: 'hashed'},
        'withHash'
      );

    response = await pluginLocal.verify(request, 'withSaltedHash', 'saltedHash');
    should(response).eql({kuid: 'withSaltedHash'});
    should(pluginLocal.update)
      .be.calledWith(
        request,
        {password: 'saltedHash'},
        'withSaltedHash'
      );

    response = await pluginLocal.verify(request, 'withoutEncryption', 'bar');
    should(response).eql({kuid: 'withoutEncryption'});
    should(pluginLocal.update)
      .be.calledWith(
        request,
        {password: 'bar'},
        'withoutEncryption'
      );
  });

  it('should throw an error if no user was found for the given username', () => {
    return should(pluginLocal.verify(null, 'ghost', 'bar')).be.fulfilledWith({
      kuid: null,
      message: 'wrong username or password'
    });
  });

  it('should throw an error if the user password has been encrypted with an unknown algorithm', () => {
    return should(pluginLocal.verify(null, 'unknownAlgorithm', 'cheezburger')).be.rejectedWith('Unknown encryption algorithm');
  });

  it('should throw an error if the credentials are invalid', () => {
    return should(pluginLocal.verify(null, 'foo', 'rab')).be.fulfilledWith({
      kuid: null,
      message: 'wrong username or password'
    });
  });

  describe('#policies - expires after', () => {
    let delay = 0;

    beforeEach(async () => {
      pluginLocal.config.passwordPolicies = [
        {
          appliesTo: '*',
          expiresAfter: '42m'
        }
      ];

      const user = await pluginLocal.getUsersRepository().get('foo');
      pluginLocal.userRepository.get = async () => {
        user._kuzzle_info.updatedAt = Date.now() - delay;
        return user;
      };
    });

    it('should allow login in if the password is not expired', async () => {
      delay = 1000 * 60 * 41;

      const response = await pluginLocal.verify(request, 'foo', 'bar');
      should(response).eql({kuid: 'foo'});
    });

    it('should throw if the password is expired', () => {
      delay = 1000 * 60 * 42 + 1;

      return pluginLocal.verify(request, 'foo', 'bar')
        .then(() => {
          throw new Error('should not happen');
        })
        .catch(error => {
          should(error).match({
            status: 401,
            id: 'plugin.kuzzle-plugin-auth-passport-local.expired_password',
            code: 0x004000001
          });

          should(
            jsonwebtoken.verify(
              error.resetToken,
              pluginLocal.config.resetPasswordSecret
            ).resetForKuid
          ).eql('foo');
        });
    });
  });

  describe('#policies - must change password', () => {
    let who;

    beforeEach(async () => {
      pluginLocal.config.passwordPolicies = [
        {
          appliesTo: '*',
          mustChangePasswordIfSetByAdmin: true
        }
      ];

      const user = await pluginLocal.userRepository.get('foo');
      who = user.kuid;

      pluginLocal.userRepository.get = async () => {
        user.updater = who;
        return user;
      };
    });

    it('should allow login in if the password was self-updated', async () => {
      const response = await pluginLocal.verify(request, 'foo', 'bar');

      should(response).eql({kuid: 'foo'});
    });

    it('should allow login in if the user is an admin', async () => {
      who = 'someone else';

      pluginContext.accessors.sdk.security.mGetProfiles.onCall(
        pluginContext.accessors.sdk.security.mGetProfiles.callCount
      ).resolves([
        {
          _id: 'admin',
          policies: [ {roleId: 'admin'} ]
        }
      ]);

      const response = await pluginLocal.verify(request, 'foo', 'bar');

      should(response).eql({kuid: 'foo'});
    });

    it('should throw if the password must be changed', () => {
      who = 'someone else';

      return pluginLocal.verify(request, 'foo', 'bar')
        .then(() => {
          throw new Error('should not happen');
        })
        .catch(error => {
          should(error).match({
            status: 401,
            id: 'plugin.kuzzle-plugin-auth-passport-local.must_change_password',
            code: 0x004000005
          });

          should(
            jsonwebtoken.verify(
              error.resetToken,
              pluginLocal.config.resetPasswordSecret
            ).resetForKuid
          ).eql('foo');
        });

    });

  });
});
