const
  should = require('should'),
  PluginLocal = require('../lib');

describe('#create', () => {
  let
    pluginLocal,
    pluginContext = require('./mock/pluginContext.mock.js'),
    repository = require('./mock/repository.mock.js');

  beforeEach(() => {
    pluginLocal = new PluginLocal();
    pluginLocal.getUsersRepository = repository;
    pluginLocal.passwordManager = require('./mock/passwordManager.mock');
    pluginLocal.context = pluginContext;
  });

  it('should return a user object if the user doesn\'t exists', () => {
    pluginLocal.getUsersRepository = () => {
      return {
        search: () => Promise.resolve({total: 0, hits: []}),
        create: () => Promise.resolve({_id: 'foo'})
      };
    };

    return should(pluginLocal.create(null, {username: 'foo', password: 'bar'}, 'foo')).be.fulfilledWith({username: 'foo'});
  });

  it('should throw an error if the user already exists', () => {
    return should(pluginLocal.create(null, {username: 'foo', password: 'bar'}, 'foo')).be.rejected({message: 'A strategy already exists for this user.'});
  });
});
