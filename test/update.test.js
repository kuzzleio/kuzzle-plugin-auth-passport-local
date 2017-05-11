const
  should = require('should'),
  PluginLocal = require('../lib'),
  sandbox = require('sinon').sandbox.create();

describe('#update', () => {
  const
    pluginContext = require('./mock/pluginContext.mock.js'),
    Repository = require('./mock/repository.mock.js');
  let pluginLocal;

  beforeEach(() => {
    sandbox.reset();
    pluginLocal = new PluginLocal();
    pluginLocal.userRepository = new Repository();
    pluginLocal.passwordManager = {
      encryptPassword: sandbox.stub().callsFake(password => password)
    };
    pluginLocal.context = pluginContext;
  });

  it('should throw an error if the user doesn\'t exists', () => {
    pluginLocal.userRepository.search = () => Promise.resolve({total: 0, hits: []});

    return should(pluginLocal.update(null, {username: 'foo', password: 'bar'}, 'foo')).be.rejectedWith('A strategy does not exist for this user.');
  });

  it('should update the user and its username if the credentials are valid', () => {
    return should(pluginLocal.update(null, {username: 'foo', password: 'bar'}, 'foo')).be.fulfilledWith({username: 'foo', kuid: 'someId'});
  });

  it('should update the user if the credentials are valid', () => {
    pluginLocal.userRepository.get = id => Promise.resolve({_id: id, kuid: 'someId'});
    pluginLocal.userRepository.search = () => Promise.resolve({total: 1, hits: [{_id: 'foo', kuid: 'someId'}]});
    pluginLocal.userRepository.update = () => Promise.resolve({_id: 'foo', kuid: 'someId'});

    return should(pluginLocal.update(null, {username: 'foo', password: 'bar'}, 'foo')).be.fulfilledWith({username: 'foo', kuid: 'someId'});
  });
});
