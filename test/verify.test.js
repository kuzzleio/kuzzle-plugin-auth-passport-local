const
  should = require('should'),
  PluginLocal = require('../lib');

describe('#verify', () => {
  const Repository = require('./mock/repository.mock.js');
  let pluginLocal;

  beforeEach(() => {
    pluginLocal = new PluginLocal();
    pluginLocal.userRepository = new Repository();
    pluginLocal.passwordManager = require('./mock/passwordManager.mock');
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
