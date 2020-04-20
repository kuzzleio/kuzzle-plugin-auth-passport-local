const
  should = require('should'),
  sinon = require('sinon'),
  PluginLocal = require('../lib'),
  PluginContext = require('./mock/pluginContext.mock.js');

describe('#verify', () => {
  const pluginContext = new PluginContext();
  let
    pluginLocal,
    request;

  beforeEach(async () => {
    pluginLocal = new PluginLocal();
    await pluginLocal.init({}, pluginContext);
    pluginLocal.userRepository = new (require('./mock/getUserRepository.mock')(pluginLocal))();

    request = new pluginContext.constructors.Request({});
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
});
