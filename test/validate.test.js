const
  should = require('should'),
  PluginLocal = require('../lib'),
  PluginContext = require('./mock/pluginContext.mock.js');

describe('#validate', () => {
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
});
