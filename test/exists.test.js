const
  should = require('should'),
  PluginLocal = require('../lib');

describe('#exists', () => {
  const
    pluginContext = require('./mock/pluginContext.mock.js'),
    Repository = require('./mock/repository.mock.js');
  let pluginLocal;

  beforeEach(() => {
    pluginLocal = new PluginLocal();
    pluginLocal.userRepository = new Repository();
    pluginLocal.context = pluginContext;
  });

  it('should return true if the user already exists', () => {
    return should(pluginLocal.exists(null, 'foo')).be.fulfilledWith(true);
  });

  it('should return false if the user doesn\'t exists', () => {
    pluginLocal.userRepository.search = () => Promise.resolve({total: 0, hits: []});

    return should(pluginLocal.exists(null, 'foo')).be.fulfilledWith(false);
  });
});
