const
  should = require('should'),
  PluginLocal = require('../lib'),
  PluginContext = require('./mock/pluginContext.mock.js');

describe('#getInfo', () => {
  const pluginContext = new PluginContext();
  let
    pluginLocal,
    request;

  beforeEach(() => {
    pluginLocal = new PluginLocal();
    pluginLocal.init({}, pluginContext);
    pluginLocal.userRepository = new (require('./mock/getUserRepository.mock')(pluginLocal))();

    request = new pluginContext.constructors.Request({});
  });

  it('should return a user object if the user exists', async () => {
    const response = await pluginLocal.getInfo(request, 'foo');

    should(response).eql({
      kuid: 'foo',
      username: 'foo'
    });
  });

  it('should throw an error if the user doesn\'t exists', () => {
    pluginLocal.userRepository.get = () => Promise.resolve(null);

    return should(pluginLocal.getInfo(request, 'foo'))
      .be.rejectedWith({message: 'No credentials found for user "foo".'});
  });
});
