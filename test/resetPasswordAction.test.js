const jsonwebtoken = require('jsonwebtoken');
const should = require('should');
const sinon = require('sinon');
const { KuzzleRequest } = require('kuzzle');

const PluginLocal = require('../lib');
const PluginContext = require('./mock/pluginContext.mock.js');

describe('#resetPasswordAction', () => {
  let
    pluginLocal,
    pluginContext,
    request;

  beforeEach(async () => {
    pluginContext = new PluginContext();
    pluginLocal = new PluginLocal();
    await pluginLocal.init({}, pluginContext);
    pluginLocal.userRepository = new (require('./mock/getUserRepository.mock')(pluginLocal))();

    request = new KuzzleRequest({
      body: {
        password: 'password',
        token: jsonwebtoken.sign(
          {kuid: 'kuid'},
          pluginLocal.config.resetPasswordSecret,
          {
            expiresIn: pluginLocal.config.resetPasswordExpiresIn,
            issuer: 'kuzzle-plugin-auth-passport-local'
          }
        )
      }
    });
  });

  it('should throw if no body is given', () => {
    const req = new KuzzleRequest({});

    return should(pluginLocal.resetPasswordAction(req))
      .be.rejected();
  });

  it('should throw if password is not set', () => {
    delete request.input.body.password;

    return should(pluginLocal.resetPasswordAction(request))
      .be.rejected();
  });

  it('should throw if password is not a string', () => {
    request.input.body.password = [];

    return should(pluginLocal.resetPasswordAction(request))
      .be.rejected();
  });

  it('should throw if the password is an empty string', () => {
    request.input.body.password = '  ';

    return should(pluginLocal.resetPasswordAction(request))
      .be.rejected();
  });

  it('should throw if the token is missing', () => {
    delete request.input.body.token;

    return should(pluginLocal.resetPasswordAction(request))
      .be.rejected();
  });

  it('should throw if the token is not a string', () => {
    request.input.body.token = true;

    return should(pluginLocal.resetPasswordAction(request))
      .be.rejected();
  });

  it('should update the password when ok', async () => {
    pluginLocal.validate = sinon.stub().resolves(true);
    pluginLocal.update = sinon.stub().resolves({kuid: 'kuid'});

    const response = await pluginLocal.resetPasswordAction(request);

    should(pluginLocal.validate)
      .be.calledOnce();
    should(pluginLocal.update)
      .be.calledOnce();

    should(pluginLocal.context.accessors.execute)
      .be.calledOnce();

    const loginRequest = pluginLocal.context.accessors.execute.firstCall.args[0];

    should(loginRequest.input).match({
      action: 'login',
      controller: 'auth',
      body: {
        password: 'password',
        username: 'foo2'
      }
    });

    should(response).eql(
      (await pluginLocal.context.accessors.execute.firstCall.returnValue).result
    );
  });

});
