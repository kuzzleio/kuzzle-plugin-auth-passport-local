const
  should = require('should'),
  PluginLocal = require('../lib'),
  sandbox = require('sinon').sandbox.create();

describe('#update', () => {
  let
    pluginLocal,
    pluginContext = require('./mock/pluginContext.mock.js'),
    repository = require('./mock/repository.mock.js');

  beforeEach(() => {
    sandbox.reset();
    pluginLocal = new PluginLocal();
    pluginLocal.getUsersRepository = repository;
    pluginLocal.passwordManager = {
      encryptPassword: sandbox.stub().callsFake(password => password)
    };
    pluginLocal.context = pluginContext;
  });

  it('should throw an error if the user doesn\'t exists', () => {
    pluginLocal.getUsersRepository = () => {
      return {
        search: () => Promise.resolve({total: 0, hits: []})
      };
    };

    return should(pluginLocal.update(null, {username: 'foo', password: 'bar'}, 'foo')).be.rejectedWith('A strategy does not exist for this user.');
  });

  it('it should update the user and its username if the credentials are valid', () => {
    return should(pluginLocal.update(null, {username: 'foo', password: 'bar'}, 'foo')).be.fulfilledWith({username: 'foo'});
  });

  it('it should update the user if the credentials are valid', () => {
    pluginLocal.getUsersRepository = sandbox.stub().returns({
      get: userId => Promise.resolve({userId: userId}),
      search: () => Promise.resolve({total: 1, hits: [{_id: 'foo'}]}),
      update: () => Promise.resolve({_id: 'foo'})
    });

    return should(pluginLocal.update(null, {username: 'foo', password: 'bar'}, 'foo')).be.fulfilledWith({username: 'foo'});
  });
});
