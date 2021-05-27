const should = require('should');
const PluginContext = require('./mock/pluginContext.mock.js');
const PluginLocal = require('../lib');
const sinon = require('sinon');
const { KuzzleRequest } = require('kuzzle');

describe('#update', () => {
  const pluginContext = new PluginContext();
  let pluginLocal;
  let request;

  beforeEach(async () => {
    pluginLocal = new PluginLocal();
    await pluginLocal.init({}, pluginContext);
    pluginLocal.userRepository = new (require('./mock/getUserRepository.mock')(pluginLocal))();

    pluginLocal.passwordManager.encryptPassword = sinon.stub().resolvesArg(0);

    request = new KuzzleRequest({controller: 'auth'});
  });

  it('should throw an error if the user doesn\'t exist', () => {
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

  it('should store the password history and truncate it to the desired length', async () => {
    pluginLocal.getCredentialsFromUserId = async () => {
      const user = new pluginLocal.User();
      user._id = 'foo';
      user.kuid = 'kuid';
      user.userPassword = 'current password';
      user._kuzzle_info = {
        updatedAt: 0
      };

      for (let i = 0; i < 12; i++) {
        user.passwordHistory.push({
          userPassword: `password ${i}`
        });
      }

      return user;
    };

    pluginLocal.config.passwordPolicies = [
      {
        appliesTo: '*',
        forbidReusedPasswordCount: 5
      }
    ];

    await pluginLocal.update(
      request,
      {username: 'foo', password: 'bar'},
      'kuid'
    );

    const updated = pluginLocal.userRepository.update.firstCall.args[0];

    should(updated.passwordHistory)
      .have.length(4); // count - 1 as the current password is taken into account during check
    should(updated.passwordHistory[0].userPassword)
      .eql('current password');
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
      const promise = pluginLocal.update(request, {
        username: 'foo',
        password: 'bar',
      });

      return should(promise).rejectedWith('Cannot update credentials: password required.');
    });

    it('should reject if an empty password is provided', async () => {
      request.input.body = {currentPassword: ''};
      let promise = pluginLocal.update(request, {
        username: 'foo',
        password: 'bar',
      });

      await should(promise).rejectedWith('Cannot update credentials: password required.');

      // @deprecated
      request.input.body = null;
      request.input.args.password = '';

      promise = pluginLocal.update(request, {
        username: 'foo',
        password: 'bar',
      });

      await should(promise).rejectedWith('Cannot update credentials: password required.');
    });

    it('should accept if no password is provided but the request is not from the auth controller', () => {
      request = new KuzzleRequest({});
      request.input.body = {currentPassword: ''};
      return should(pluginLocal.update(request, {username: 'foo', 'password': 'bar'}))
        .fulfilled();
    });

    it('should reject if the password is invalid', async () => {
      pluginLocal.passwordManager.checkPassword.returns(false);

      request.input.body = {currentPassword: 'ohnoes'};
      let promise = pluginLocal.update(request, {
        username: 'foo',
        password: 'bar',
      });

      await should(promise).rejectedWith('Invalid user or password.');

      // @deprecated
      request.input.body = null;
      request.input.args.password = 'ohnoes';
      promise = pluginLocal.update(request, {
        username: 'foo',
        password: 'bar',
      });
      await should(promise).rejectedWith('Invalid user or password.');
    });
  });
});
