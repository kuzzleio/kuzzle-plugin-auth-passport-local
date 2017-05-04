const
  should = require('should'),
  PluginLocal = require('../lib');

describe('#delete', () => {
  let
    pluginLocal,
    pluginContext = require('./mock/pluginContext.mock.js'),
    repository = require('./mock/repository.mock.js');

  beforeEach(() => {
    pluginLocal = new PluginLocal();
    pluginLocal.getUsersRepository = repository;
    pluginLocal.context = pluginContext;
  });

  it('should return true if the user exists', () => {
    return should(pluginLocal.delete(null, 'foo')).be.fulfilledWith(true);
  });

  it('should throw an error if the user doesn\'t exists', () => {
    pluginLocal.getUsersRepository = () => {
      return {
        search: () => Promise.resolve({total: 0, hits: []})
      };
    };

    return should(pluginLocal.delete(null, 'ghost')).be.rejectedWith({message: 'A strategy does not exist for this user.'});
  });
});
