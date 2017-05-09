const
  should = require('should'),
  PluginLocal = require('../lib');

describe('#getInfo', () => {
  const
    pluginContext = require('./mock/pluginContext.mock.js'),
    repository = require('./mock/repository.mock.js');
  let pluginLocal;

  beforeEach(() => {
    pluginLocal = new PluginLocal();
    pluginLocal.getUsersRepository = repository;
    pluginLocal.context = pluginContext;
  });

  it('should return a user object if the user exists', () => {
    return should(pluginLocal.getInfo(null, 'foo')).be.fulfilledWith({username: 'foo2'});
  });

  it('should throw an error if the user doesn\'t exists', () => {
    pluginLocal.getUsersRepository = () => {
      return {
        search: () => Promise.resolve({total: 0, hits: []})
      };
    };

    return should(pluginLocal.getInfo(null, 'foo')).be.rejectedWith({message: 'A strategy does not exist for this user.'});
  });
});
