const should = require('should');
const PluginLocal = require('../lib');
const PluginContext = require('./mock/pluginContext.mock.js');
const { KuzzleRequest } = require('kuzzle');

describe('#getInfo', () => {
  const pluginContext = new PluginContext();
  let
    pluginLocal,
    request;

  beforeEach(() => {
    pluginLocal = new PluginLocal();
    pluginLocal.init({}, pluginContext);
    pluginLocal.userRepository = new (require('./mock/getUserRepository.mock')(pluginLocal))();

    request = new KuzzleRequest({});
  });

  it('should return a user object if the user exists', async () => {
    const response = await pluginLocal.getInfo(request, 'foo');

    should(response).eql({
      kuid: 'someId',
      username: 'foo2'
    });
  });

  it('should throw an error if the user doesn\'t exists', () => {
    pluginLocal.userRepository.search.resolves({total: 0, hits: []});

    return should(pluginLocal.getInfo(request, 'foo'))
      .be.rejectedWith({message: 'No credentials found for user "foo".'});
  });
});
