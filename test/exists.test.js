const should = require('should');
const { KuzzleRequest } = require('kuzzle');

const PluginLocal = require('../lib');
const PluginContext = require('./mock/pluginContext.mock.js');

describe('#exists', () => {
  const pluginContext = new PluginContext();
  let
    pluginLocal,
    request;

  beforeEach(async () => {
    pluginLocal = new PluginLocal();
    await pluginLocal.init({}, pluginContext);
    pluginLocal.userRepository = new (require('./mock/getUserRepository.mock')(pluginLocal))();

    request = new KuzzleRequest({});
  });

  it('should return true if the user already exists', () => {
    return should(pluginLocal.exists(request, 'foo')).be.fulfilledWith(true);
  });

  it('should return false if the user doesn\'t exists', () => {
    pluginLocal.userRepository.search = () => Promise.resolve({total: 0, hits: []});

    return should(pluginLocal.exists(request, 'foo')).be.fulfilledWith(false);
  });
});
