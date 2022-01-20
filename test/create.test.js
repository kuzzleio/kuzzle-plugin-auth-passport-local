const should = require('should');
const { KuzzleRequest } = require('kuzzle');

const PluginLocal = require('../lib');
const PluginContext = require('./mock/pluginContext.mock.js');

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

  it('should create and return a user object if the user doesn\'t exists', async () => {
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
    should(pluginLocal.userRepository.create).be.calledWithMatch(
      {
        kuid: 'foo',
        _id: 'foo',
        algorithm: 'sha512',
        stretching: true,
        pepper: false,
        encryption: 'hmac',
        updater: null
      },
      {
        refresh: 'wait_for',
      }
    )
  });

  it('should propagate refresh option', async () => {
    request.input.args.refresh = 'false';
    pluginLocal.userRepository.search = () => Promise.resolve({total: 0, hits: []});

    await pluginLocal.create(
      request,
      {username: 'foo', password: 'bar'},
      'foo'
    );

    should(pluginLocal.userRepository.create).be.calledWithMatch({}, { refresh: 'false' });
  });

  it('should throw an error if the user already exists', () => {
    return should(pluginLocal.create(request, {username: 'foo', password: 'bar'}, 'foo'))
      .be.rejectedWith({message: 'A strategy already exists for user "foo".'});
  });
});
