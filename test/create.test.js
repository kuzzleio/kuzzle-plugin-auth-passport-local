const
  should = require('should'),
  PluginLocal = require('../lib');

describe('#create', () => {
  const
    pluginContext = require('./mock/pluginContext.mock.js'),
    Repository = require('./mock/repository.mock.js');
  let pluginLocal;

  beforeEach(() => {
    pluginLocal = new PluginLocal();
    pluginLocal.userRepository = new Repository();
    pluginLocal.passwordManager = require('./mock/passwordManager.mock');
    pluginLocal.context = pluginContext;
  });

  it('should return a user object if the user doesn\'t exists', () => {
    pluginLocal.userRepository.search = () => Promise.resolve({total: 0, hits: []});

    return should(pluginLocal.create(null, {username: 'foo', password: 'bar'}, 'foo')).be.fulfilledWith({kuid:'someId', username: 'foo'});
  });

  it('should throw an error if the user already exists', () => {
    return should(pluginLocal.create(null, {username: 'foo', password: 'bar'}, 'foo')).be.rejected({message: 'A strategy already exists for this user.'});
  });
});
