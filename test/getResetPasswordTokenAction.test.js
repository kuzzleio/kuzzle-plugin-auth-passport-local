const
  jsonwebtoken = require('jsonwebtoken'),
  should = require('should'),
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
      _id: 'kuid'
    });
  });

  it('should throw if the kuid is missing', () => {
    const req = new pluginContext.constructors.Request({});

    return should(pluginLocal.getResetPasswordTokenAction(req))
      .be.rejectedWith(pluginContext.errors.BadRequestError);
  });

  it('should throw if the kuid is an empty string', () => {
    request.input.resource._id = '';

    return should(pluginLocal.getResetPasswordTokenAction(request))
      .be.rejectedWith(pluginContext.errors.BadRequestError);
  });

  it('should throw if the user does not exist', () => {
    pluginLocal.userRepository.search.resolves({
      total: 0,
      hits: []
    });

    return should(pluginLocal.getResetPasswordTokenAction(request))
      .be.rejectedWith(pluginContext.errors.BadRequestError);
  });

  it('should return a token if the kuid is valid', async () => {
    const response = await pluginLocal.getResetPasswordTokenAction(request);
    const parsed = jsonwebtoken.verify(
      response.resetToken,
      pluginLocal.config.resetPasswordSecret
    );

    should(parsed).match({
      resetForKuid: 'kuid',
      iss: 'kuzzle-plugin-auth-passport-local'
    });

    should(parsed.exp - parsed.iat).eql(pluginLocal.config.resetPasswordExpiresIn);
  });
});
