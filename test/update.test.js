const
  should = require('should'),
  PluginContext = require('./mock/pluginContext.mock.js'),
  PluginLocal = require('../lib'),
  sinon = require('sinon');

describe('#update', () => {
  const pluginContext = new PluginContext();
  let
    pluginLocal,
    request;

  beforeEach(async () => {
    pluginLocal = new PluginLocal();
    await pluginLocal.init({}, pluginContext);
    pluginLocal.userRepository = new (require('./mock/getUserRepository.mock')(pluginLocal))();

    pluginLocal.passwordManager.encryptPassword = sinon.stub().resolvesArg(0);

    request = new pluginContext.constructors.Request({});
  });

  it('should throw an error if the user doesn\'t exists', () => {
    pluginLocal.userRepository.search.resolves({total: 0, hits: []});

    return should(pluginLocal.update(request, {username: 'foo', password: 'bar'}, 'foo'))
      .be.rejectedWith('No credentials found for user "foo".');
  });

  it('should update the user and its username if the credentials are valid', async () => {
    const response = await pluginLocal.update(
      request,
      {username: 'foo', password: 'bar'},
      'foo'
    );

    should(pluginLocal.getUsersRepository().create)
      .be.calledOnce();

    should(response).eql({
      kuid: 'someId',
      username: 'foo'
    });
  });

  it('should update the user if the credentials are valid', async () => {
    const response = await pluginLocal.update(
      request,
      {username: 'foo2', password: 'bar'},
      'foo'
    );

    should(pluginLocal.getUsersRepository().update)
      .be.calledOnce();

    should(response).eql({
      kuid: 'someId',
      username: 'foo2'
    });
  });

  describe('#requirePassword', () => {
    beforeEach(() => {
      pluginLocal.userRepository.search.returns({
        total: 1,
        hits: [
          pluginLocal.userRepository.fromDTO({_id: 'foo', kuid: 'someId'})
        ]
      });
      pluginLocal.config.requirePassword = true;
      pluginLocal.passwordManager.checkPassword = sinon.stub().returns(true);
    });

    it('should reject if no password is provided', () => {
      return should(pluginLocal.update(request, {username: 'foo', 'password': 'bar'}))
        .rejectedWith('Cannot update credentials: password required.');
    });

    it('should reject if an empty password is provided', () => {
      request.input.args.password = '';
      return should(pluginLocal.update(request, {username: 'foo', 'password': 'bar'}))
        .rejectedWith('Cannot update credentials: password required.');
    });

    it('should accept if no password is provided but the request is from the security controller', () => {
      request.input.args.password = '';
      request.input.controller = 'security';
      return should(pluginLocal.update(request, {username: 'foo', 'password': 'bar'}))
        .fulfilled();
    });

    it('should reject if the password is invalid', () => {
      request.input.args.password = 'ohnoes';
      pluginLocal.passwordManager.checkPassword.returns(false);
      return should(pluginLocal.update(request, {username: 'foo', 'password': 'bar'}))
        .rejectedWith('Invalid user or password.');
    });
  });
});
