const should = require('should');
const PluginLocal = require('../lib');
const PluginContext = require('./mock/pluginContext.mock.js');
const { KuzzleRequest } = require('kuzzle');

describe('#create', () => {
  const pluginContext = new PluginContext();
  let
    pluginLocal,
    request;

  beforeEach(async () => {
    pluginLocal = new PluginLocal();
    await pluginLocal.init({}, pluginContext);
    pluginLocal.userRepository = new (require('./mock/getUserRepository.mock')(pluginLocal));

    request = new KuzzleRequest({});
  });

  it('should return a user object if the user doesn\'t exists', async () => {
    pluginLocal.userRepository.search = () => Promise.resolve({total: 0, hits: []});

    const response = await pluginLocal.create(
      request,
      {username: 'foo', password: 'bar'},
      'foo'
    );

    should(response).eql({
      kuid: 'someId',
      username: 'foo'
    });
  });

  it('should throw an error if the user already exists', () => {
    return should(pluginLocal.create(request, {username: 'foo', password: 'bar'}, 'foo'))
      .be.rejectedWith({message: 'A strategy already exists for user "foo".'});
  });
});
