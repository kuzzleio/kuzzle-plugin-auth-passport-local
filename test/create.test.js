const
  should = require('should'),
  PluginLocal = require('../lib'),
  PluginContext = require('./mock/pluginContext.mock.js');

describe('#create', () => {
  const pluginContext = new PluginContext();
  let
    pluginLocal,
    request;

  beforeEach(async () => {
    pluginLocal = new PluginLocal();
    await pluginLocal.init({}, pluginContext);
    pluginLocal.userRepository = new (require('./mock/getUserRepository.mock')(pluginLocal));

    request = new pluginContext.constructors.Request({});
  });

  it('should return a user object if the user doesn\'t exists', async () => {
    pluginLocal.userRepository.get = () => Promise.resolve(null);

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
