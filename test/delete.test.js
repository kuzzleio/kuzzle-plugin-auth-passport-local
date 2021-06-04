const should = require('should');
const sinon = require('sinon');
const { KuzzleRequest } = require('kuzzle');

const PluginLocal = require('../lib');
const PluginContext = require('./mock/pluginContext.mock.js');

describe('#delete', () => {
  const pluginContext = new PluginContext();
  let pluginLocal;
  let request;

  beforeEach(async () => {
    pluginLocal = new PluginLocal();
    await pluginLocal.init({
      requirePassword: false
    }, pluginContext);
    pluginLocal.userRepository = new (require('./mock/getUserRepository.mock')(pluginLocal))();

    request = new KuzzleRequest({controller: 'auth'});
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
      const promise = pluginLocal.delete(request, {
        username: 'foo',
        password: 'bar',
      });

      return should(promise).rejectedWith('Cannot update credentials: password required.');
    });

    it('should reject if an empty password is provided', async () => {
      request.input.body = {currentPassword: ''};
      let promise = pluginLocal.delete(request, {
        username: 'foo',
        password: 'bar',
      });

      await should(promise).rejectedWith('Cannot update credentials: password required.');

      // @deprecated
      request.input.body = null;
      request.input.args.password = '';

      promise = pluginLocal.delete(request, {
        username: 'foo',
        password: 'bar',
      });

      await should(promise).rejectedWith('Cannot update credentials: password required.');
    });

    it('should accept if no password is provided but the request is not from the auth controller', () => {
      request = new KuzzleRequest({});
      request.input.body = {currentPassword: ''};

      return should(pluginLocal.delete(request, {username: 'foo', 'password': 'bar'}))
        .fulfilled();
    });

    it('should reject if the password is invalid', async () => {
      pluginLocal.passwordManager.checkPassword.returns(false);

      request.input.body = {currentPassword: 'ohnoes'};
      let promise = pluginLocal.delete(request, {
        username: 'foo',
        password: 'bar',
      });

      await should(promise).rejectedWith('Invalid user or password.');

      // @deprecated
      request.input.body = null;
      request.input.args.password = 'ohnoes';
      promise = pluginLocal.delete(request, {
        username: 'foo',
        password: 'bar',
      });
      await should(promise).rejectedWith('Invalid user or password.');
    });
  });
});
