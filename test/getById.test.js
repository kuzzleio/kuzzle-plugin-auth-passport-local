const
  should = require('should'),
  PluginLocal = require('../lib');

describe('#getById', () => {
  const
    pluginContext = require('./mock/pluginContext.mock.js'),
    Repository = require('./mock/repository.mock.js');
  let pluginLocal;

  beforeEach(() => {
    pluginLocal = new PluginLocal();
    pluginLocal.userRepository = new Repository();
    pluginLocal.context = pluginContext;
  });

  it('should return a user object if the user exists', () => {
    return should(pluginLocal.getById(null, 'foo')).be.fulfilledWith({username: 'foo', kuid: 'foo'});
  });

  it('should throw an error if the user doesn\'t exists', () => {
    pluginLocal.userRepository.get = () => Promise.resolve(null);

    return should(pluginLocal.getById(null, 'foo')).be.rejectedWith({message: 'A strategy does not exist for this username.'});
  });
});
