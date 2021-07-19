const should = require('should');
const { KuzzleRequest } = require('kuzzle');

const PluginLocal = require('../lib');
const PluginContext = require('./mock/pluginContext.mock.js');

describe('#getById', () => {
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

  it('should return a user object if the user exists', async () => {
    const user = await pluginLocal.getById(request, 'foo');

    should(user).eql({
      kuid: 'foo',
      username: 'foo'
    });
  });

  it('should throw an error if the user doesn\'t exists', () => {
    pluginLocal.userRepository.get = () => Promise.resolve(null);

    return should(pluginLocal.getById(request, 'foo'))
      .be.rejectedWith({message: 'No credentials found for username "foo".'});
  });
});
