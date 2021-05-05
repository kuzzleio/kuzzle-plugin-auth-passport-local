const
  should = require('should'),
  PluginLocal = require('../lib'),
  PluginContext = require('./mock/pluginContext.mock.js');

describe('#getById', () => {
  const pluginContext = new PluginContext();
  let
    pluginLocal,
    request;

  beforeEach(async () => {
    pluginLocal = new PluginLocal();
    await pluginLocal.init({}, pluginContext);
    pluginLocal.userRepository = new (require('./mock/getUserRepository.mock')(pluginLocal))();

    request = new pluginContext.constructors.Request({});
  });

  it('should return a user object if the user exists', async () => {
    const user = await pluginLocal.getById(request, 'foo');

    should(user).eql({
      kuid: 'someId',
      username: 'foo2'
    });
  });

  it('should throw an error if the user doesn\'t exists', () => {
    pluginLocal.userRepository.search = () => Promise.resolve({ total: 0, hits: []});

    return should(pluginLocal.getById(request, 'foo'))
      .be.rejectedWith({message: 'No credentials found for username "foo".'});
  });
});
