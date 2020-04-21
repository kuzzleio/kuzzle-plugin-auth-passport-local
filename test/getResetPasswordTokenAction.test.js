const
  jsonwebtoken = require('jsonwebtoken'),
  should = require('should'),
  sinon = require('sinon'),
  PluginLocal = require('../lib'),
  PluginContext = require('./mock/pluginContext.mock.js');

describe('#getResetPasswordTokenAction', () => {
  let
    pluginLocal,
    pluginContext,
    request;

  beforeEach(async () => {
    pluginContext = new PluginContext();
    pluginLocal = new PluginLocal();
    await pluginLocal.init({}, pluginContext);
    pluginLocal.userRepository = new (require('./mock/getUserRepository.mock')(pluginLocal))();

    request = new pluginContext.constructors.Request({
      kuid: 'kuid'
    });
  });

  it('should throw if the kuid is missing', () => {
    delete request.input.args.kuid;

    return should(pluginLocal.getResetPasswordTokenAction(request))
      .be.rejectedWith(pluginLocal.errors.BadRequestError);
  });

  it('should throw if the kuid is an empty string', () => {
    request.input.args.kuid = '';

    return should(pluginLocal.getResetPasswordTokenAction(request))
      .be.rejectedWith(pluginLocal.errors.BadRequestError);
  });

  it('should throw if the kuid is not a string', () => {
    request.input.args.kuid = [true];

    return should(pluginLocal.getResetPasswordTokenAction(request))
      .be.rejectedWith(pluginLocal.errors.BadRequestError);
  });

  it('should throw if the user does not exist', () => {
    pluginLocal.userRepository.search.resolves({
      total: 0,
      hits: []
    });

    return should(pluginLocal.getResetPasswordTokenAction(request))
      .be.rejectedWith(pluginLocal.errors.BadRequestError);
  });

  it('should return a token if the kuid is valid', async () => {
    const response = await pluginLocal.getResetPasswordTokenAction(request);
    const parsed = jsonwebtoken.verify(
      response.resetToken,
      pluginLocal.config.resetPasswordSecret
    );

    should(parsed).match({
      kuid: 'kuid',
      iss: 'kuzzle-plugin-auth-passport-local'
    });

    should(parsed.exp - parsed.iat).eql(pluginLocal.config.resetPasswordExpiresIn);
  });
});
