const
  should = require('should'),
  sinon = require('sinon'),
  PluginLocal = require('../lib'),
  PluginContext = require('./mock/pluginContext.mock.js');

describe('#delete', () => {
  const
    pluginContext = new PluginContext(),
    Repository = require('./mock/repository.mock.js');
  let pluginLocal;

  beforeEach(() => {
    pluginLocal = new PluginLocal();
    pluginLocal.userRepository = new Repository();
    pluginLocal.context = pluginContext;
    pluginLocal.config = { requirePassword: false };
  });

  it('should return true if the user exists', () => {
    return should(pluginLocal.delete(null, 'foo')).be.fulfilled();
  });

  it('should throw an error if the user doesn\'t exists', () => {
    pluginLocal.userRepository.search = () => Promise.resolve({total: 0, hits: []});

    return should(pluginLocal.delete(null, 'ghost')).be.rejectedWith({message: 'No credentials found for user "ghost".'});
  });

  describe('#requirePassword', () => {
    let request;

    beforeEach(() => {
      pluginLocal.userRepository.search = () => Promise.resolve({total: 1, hits: [{_id: 'foo', kuid: 'someId'}]});
      pluginLocal.config.requirePassword = true;
      pluginLocal.passwordManager = {checkPassword: sinon.stub().returns(true)};
      request = {input: {args: {}}};
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
