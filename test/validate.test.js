const
  should = require('should'),
  PluginLocal = require('../lib');

describe('#validate', () => {
  const
    pluginContext = require('./mock/pluginContext.mock.js'),
    repository = require('./mock/repository.mock.js');
  let pluginLocal;

  beforeEach(() => {
    pluginLocal = new PluginLocal();
    pluginLocal.getUsersRepository = repository;
    pluginLocal.context = pluginContext;
  });

  it('should throw an error if the credentials are not well-formed', () => {
    return should(pluginLocal.validate(null, {}, 'foo', false)).be.rejectedWith('Username is a mandatory field for authentication strategy "local".');
  });

  it('should throw an error if the kuid is provided in the credentials', () => {
    return should(pluginLocal.validate(null, {kuid: 'foo', username: 'bar'}, 'foo')).be.rejectedWith('kuid cannot be specified in credentials.');
  });

  it('should return true if the provided username equals the kuid', () => {
    return should(pluginLocal.validate(null, {username:'foo', password:'bar'}, 'foo')).be.fulfilledWith(true);
  });

  it('should return true if no user was found for the given kuid', () => {
    return should(pluginLocal.validate(null, {username:'ghost', password:'bar'}, 'foo')).be.fulfilledWith(true);
  });

  it('should throw an error if the provided username differs from the kuid', () => {
    return should(pluginLocal.validate(null, {username: 'bar', password: 'bar'}, 'foo')).be.rejectedWith('Login "bar" is already used.');
  });
});
