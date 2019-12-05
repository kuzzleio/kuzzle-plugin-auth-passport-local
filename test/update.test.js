const
  should = require('should'),
  PluginLocal = require('../lib'),
  sinon = require('sinon'),
  PluginContext = require('./mock/pluginContext.mock.js');

describe('#update', () => {
  const
    pluginContext = new PluginContext(),
    Repository = require('./mock/repository.mock.js');
  let pluginLocal;

  beforeEach(() => {
    pluginLocal = new PluginLocal();
    pluginLocal.userRepository = new Repository();
    pluginLocal.passwordManager = {
      encryptPassword: sinon.stub().callsFake(password => Promise.resolve(password))
    };
    pluginLocal.context = pluginContext;
    pluginLocal.config = {};
  });

  it('should throw an error if the user doesn\'t exists', () => {
    pluginLocal.userRepository.search = () => Promise.resolve({total: 0, hits: []});

    return should(pluginLocal.update(null, {username: 'foo', password: 'bar'}, 'foo'))
      .be.rejectedWith('No credentials found for user "foo".');
  });

  it('should update the user and its username if the credentials are valid', () => {
    return should(pluginLocal.update(null, {username: 'foo', password: 'bar'}, 'foo')).be.fulfilledWith({username: 'foo', kuid: 'someId'});
  });

  it('should update the user if the credentials are valid', () => {
    pluginLocal.userRepository.get = id => Promise.resolve({_id: id, kuid: 'someId'});
    pluginLocal.userRepository.search = () => Promise.resolve({total: 1, hits: [{_id: 'foo', kuid: 'someId'}]});
    pluginLocal.userRepository.update = () => Promise.resolve({_id: 'foo', kuid: 'someId'});

    return should(pluginLocal.update(null, {username: 'foo', password: 'bar'}, 'foo')).be.fulfilledWith({username: 'foo', kuid: 'someId'});
  });

  describe('#requirePassword', () => {
    let request;

    beforeEach(() => {
      pluginLocal.userRepository.search = () => Promise.resolve({total: 1, hits: [{_id: 'foo', kuid: 'someId'}]});
      pluginLocal.userRepository.update = () => Promise.resolve({_id: 'foo', kuid: 'someId'});
      pluginLocal.config.requirePassword = true;
      pluginLocal.passwordManager.checkPassword = sinon.stub().returns(true);
      request = {input: {args: {}}};
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

    it('should reject if the password is invalid', () => {
      request.input.args.password = 'ohnoes';
      pluginLocal.passwordManager.checkPassword.returns(false);
      return should(pluginLocal.update(request, {username: 'foo', 'password': 'bar'}))
        .rejectedWith('Invalid user or password.');
    });
  });
});
