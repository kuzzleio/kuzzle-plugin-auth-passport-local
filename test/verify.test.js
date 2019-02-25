const
  should = require('should'),
  sinon = require('sinon'),
  PluginLocal = require('../lib');

describe('#verify', () => {
  const Repository = require('./mock/repository.mock.js');
  let pluginLocal;

  beforeEach(() => {
    pluginLocal = new PluginLocal();
    pluginLocal.userRepository = new Repository();
    pluginLocal.passwordManager = require('./mock/passwordManager.mock');
    pluginLocal.config = {algorithm: 'sha512', stretching: true, encryption: 'hmac'};
  });

  it('should return the username if the credentials are valid', () => {
    sinon.stub(pluginLocal, 'update').returns(Promise.resolve());

    return pluginLocal.verify(null, 'foo', 'bar')
      .then(kuid => {
        should(kuid).match({kuid: 'foo'});
        should(pluginLocal.update.called).be.false();
        return pluginLocal.verify(null, 'nostretching', 'password');
      })
      .then(kuid => {
        should(kuid).match({kuid: 'nostretching'});
        should(pluginLocal.update.calledOnce).be.true();
        should(pluginLocal.update.calledWith(null, {password: 'password'}, 'nostretching')).be.true();
        return pluginLocal.verify(null, 'withHash', 'hashed');
      })
      .then(kuid => {
        should(kuid).match({kuid: 'withHash'});
        should(pluginLocal.update.calledTwice).be.true();
        should(pluginLocal.update.secondCall.calledWith(null, {password: 'hashed'}, 'withHash')).be.true();
        return pluginLocal.verify(null, 'withSaltedHash', 'saltedHash');
      })
      .then(kuid => {
        should(kuid).match({kuid: 'withSaltedHash'});
        should(pluginLocal.update.calledThrice).be.true();
        should(pluginLocal.update.thirdCall.calledWith(null, {password: 'saltedHash'}, 'withSaltedHash')).be.true();
        return pluginLocal.verify(null, 'withoutEncryption', 'bar');
      })
      .then(kuid => {
        should(kuid).match({kuid: 'withoutEncryption'});
        should(pluginLocal.update.callCount).be.eql(4);
        should(pluginLocal.update.getCall(3).calledWith(null, {password: 'bar'}, 'withoutEncryption')).be.true();
      });
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
});
