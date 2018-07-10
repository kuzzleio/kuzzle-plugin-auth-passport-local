const
  should = require('should'),
  PluginLocal = require('../lib'),
  PluginContext = require('./mock/pluginContext.mock.js');

describe('#delete', () => {
  const
    pluginContext = new PluginContext(),
    Repository = require('./mock/repository.mock.js');
  let pluginLocal;

  beforeEach(() => {
    pluginLocal = new PluginLocal();
    pluginLocal.userRepository = new Repository();
    pluginLocal.context = pluginContext;
  });

  it('should return true if the user exists', () => {
    return should(pluginLocal.delete(null, 'foo')).be.fulfilled();
  });

  it('should throw an error if the user doesn\'t exists', () => {
    pluginLocal.userRepository.search = () => Promise.resolve({total: 0, hits: []});

    return should(pluginLocal.delete(null, 'ghost')).be.rejectedWith({message: 'A strategy does not exist for user "ghost".'});
  });
});
