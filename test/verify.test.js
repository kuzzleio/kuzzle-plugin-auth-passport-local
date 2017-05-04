const
  should = require('should'),
  rewire = require('rewire'),
  PluginLocal = rewire('../lib');

describe('#verify', () => {
  let
    pluginLocal,
    pluginContext = rewire('./mock/pluginContext.mock.js'),
    repository = rewire('./mock/repository.mock.js');

  beforeEach(() => {
    pluginLocal = new PluginLocal();
    pluginLocal.getUsersRepository = repository;
    pluginLocal.passwordManager = require('./mock/passwordManager.mock');

    pluginLocal.init(null, pluginContext);
  });

  it('should return the username if the credentials are valid', () => {
    return should(pluginLocal.verify(null, 'foo', 'bar')).be.fulfilledWith('foo');
  });

  it('should throw an error if no user was found for the given username', () => {
    return should(pluginLocal.verify(null, 'ghost', 'bar')).be.fulfilledWith({message: 'wrong username or password'});
  });

  it('should throw an error if the credentials are invalid', () => {
    return should(pluginLocal.verify(null, 'foo', 'rab')).be.fulfilledWith({message: 'wrong username or password'});
  });
});
