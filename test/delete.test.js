const
  should = require('should'),
  sinon = require('sinon'),
  PluginLocal = require('../lib'),
  PluginContext = require('./mock/pluginContext.mock.js');

describe('#delete', () => {
  const pluginContext = new PluginContext();
  let
    pluginLocal,
    request;

  beforeEach(async () => {
    pluginLocal = new PluginLocal();
    await pluginLocal.init({
      requirePassword: false
    }, pluginContext);
    pluginLocal.userRepository = new (require('./mock/getUserRepository.mock')(pluginLocal))();

    request = new pluginContext.constructors.Request({});
  });

  it('should return true if the user exists', async () => {
    const response = await pluginLocal.delete(request, 'foo');

    should(response).be.true();
  });

  it('should throw an error if the user doesn\'t exists', () => {
    pluginLocal.userRepository.search.resolves({total: 0, hits: []});

    return should(pluginLocal.delete(request, 'ghost'))
      .be.rejectedWith({message: 'No credentials found for user "ghost".'});
  });

  describe('#requirePassword', () => {
    beforeEach(() => {
      pluginLocal.config.requirePassword = true;
      pluginLocal.passwordManager = {checkPassword: sinon.stub().returns(true)};
    });

    it('should reject if no password is provided', () => {
      return should(pluginLocal.delete(request, {username: 'foo', 'password': 'bar'}))
        .rejectedWith('Cannot update credentials: password required.');
    });

    it('should reject if an empty password is provided', () => {
      request.input.args.password = '';
      return should(pluginLocal.delete(request, {username: 'foo', 'password': 'bar'}))
        .rejectedWith('Cannot update credentials: password required.');
    });

    it('should accept if no password is provided but the request is from the security controller', () => {
      request.input.args.password = '';
      request.input.controller = 'security';
      return should(pluginLocal.delete(request, {username: 'foo', 'password': 'bar'}))
        .fulfilled();
    });

    it('should reject if the password is invalid', () => {
      request.input.args.password = 'ohnoes';
      pluginLocal.passwordManager.checkPassword.returns(false);
      return should(pluginLocal.delete(request, {username: 'foo', 'password': 'bar'}))
        .rejectedWith('Invalid user or password.');
    });
  });
});
