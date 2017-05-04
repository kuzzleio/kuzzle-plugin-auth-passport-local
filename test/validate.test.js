const
  should = require('should'),
  rewire = require('rewire'),
  PluginLocal = rewire('../lib');

describe('#validate', () => {
  let
    pluginLocal,
    pluginContext = rewire('./mock/pluginContext.mock.js'),
    repository = rewire('./mock/repository.mock.js');

  beforeEach(() => {
    pluginLocal = new PluginLocal();
    pluginLocal.getUsersRepository = repository;

    pluginLocal.init(null, pluginContext);
  });

  it('should throw an error if the credentials are not well-formed', () => {
    return should(pluginLocal.validate(null, {}, 'foo', false)).be.rejectedWith('Username is a mandatory field for authentication strategy "local".');
  });

  it('should throw an error if the userId is provided in the credentials', () => {
    return should(pluginLocal.validate(null, {userId: 'foo', username: 'bar'}, 'foo')).be.rejectedWith('userId cannot be specified in credentials.');
  });

  it('should return true if the provided username equals the userId', () => {
    return should(pluginLocal.validate(null, {username:'foo', password:'bar'}, 'foo')).be.fulfilledWith(true);
  });

  it('should return true if no user was found for the given userId', () => {
    return should(pluginLocal.validate(null, {username:'ghost', password:'bar'}, 'foo')).be.fulfilledWith(true);
  });

  it('should throw an error if the provided username differs from the userId', () => {
    return should(pluginLocal.validate(null, {username: 'bar', password: 'bar'}, 'foo')).be.rejectedWith('Login "bar" is already used.');
  });
});
