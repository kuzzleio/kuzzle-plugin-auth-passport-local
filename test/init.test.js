const
  assert = require('assert'),
  should = require('should'),
  PluginLocal = require('../lib'),
  PluginContext = require('./mock/pluginContext.mock.js');

describe('#init', () => {
  let
    pluginLocal,
    pluginContext;

  beforeEach(() => {
    pluginContext = new PluginContext();
    pluginLocal = new PluginLocal();
    pluginLocal.context = pluginContext;
  });

  it('should initialize a \'local\' strategy', async () => {
    should(pluginLocal.strategies).not.be.ok();

    await pluginLocal.init(null, pluginContext);

    should(pluginLocal.strategies).be.Object().and.match({
      local: {
        config: {
          authenticator: 'LocalStrategy',
          strategyOptions: {},
          authenticateOptions: {
            scope: []
          },
          fields: ['username', 'password']
        },
        methods: {
          create: 'create',
          delete: 'delete',
          exists: 'exists',
          getInfo: 'getInfo',
          update: 'update',
          validate: 'validate',
          verify: 'verify'
        }
      }
    });
  });

  it('should use a "constructor" instead if Kuzzle version is < 1.4.0', async () => {
    should(pluginLocal.strategies).not.be.ok();
    pluginContext.config.version = '1.3.9999';

    await pluginLocal.init(null, pluginContext);

    should(pluginLocal.strategies).be.Object().and.match({
      local: {
        config: {
          constructor: () => {},
          strategyOptions: {},
          authenticateOptions: {
            scope: []
          },
          fields: ['username', 'password']
        },
        methods: {
          create: 'create',
          delete: 'delete',
          exists: 'exists',
          getInfo: 'getInfo',
          update: 'update',
          validate: 'validate',
          verify: 'verify'
        }
      }
    });
  });

  it('should have a getUserRepository method returning an object', async () => {
    await pluginLocal.init(null, pluginContext);

    should(pluginLocal.getUsersRepository).be.a.Function();
    should(pluginLocal.getUsersRepository()).be.an.Object();
  });

  it('should create the resetPasswordToken if not set', async () => {
    await pluginLocal.init(null, pluginContext);

    should(pluginLocal.configRepository.get)
      .not.be.called();
  });

  it('should get the token from ES if set', async () => {
    pluginLocal.configRepository.create.rejects({
      id: 'services.storage.document_already_exists'
    });
    pluginLocal.configRepository.get.resolves({secret: 'fromES'});

    await pluginLocal.init(null, pluginContext);

    should(pluginLocal.config.resetPasswordSecret).eql('fromES');
  });

  describe('#assertions', () => {
    describe('#resetPasswordExpiresIn', () => {
      it('-1 is ok', async () => {
        await pluginLocal.init({
          resetPasswordExpiresIn: -1
        }, pluginContext);

        should(pluginLocal.config.resetPasswordExpiresIn).eql(-1);
      });

      it('a positive number is ok', async () => {
        await pluginLocal.init({
          resetPasswordExpiresIn: 42
        }, pluginContext);

        should(pluginLocal.config.resetPasswordExpiresIn).eql(42);
      });

      it('a valid time representation is ok', async () => {
        await pluginLocal.init({
          resetPasswordExpiresIn: '1d'
        }, pluginContext);

        should(pluginLocal.config.resetPasswordExpiresIn)
          .eql(1000 * 3600 * 24);
      });

      it('a negative time interval is not allowed', () => {
        return should(pluginLocal.init({
          resetPasswordExpiresIn: '-3h'
        }, pluginContext))
          .be.rejectedWith(assert.AssertionError);
      });

      it('anything weird is not allowed either', () => {
        return should(pluginLocal.init({
          resetPasswordExpiresIn: '~#'
        }, pluginContext))
          .be.rejectedWith(assert.AssertionError);
      });
    });

    describe('#passwordPolicies', () => {
      it('appliesTo can only be * if a string', () => {
        return should(pluginLocal.init({
          passwordPolicies: [
            {
              appliesTo: 'me'
            }
          ]
        }, pluginContext))
          .be.rejectedWith(assert.AssertionError);
      });

      it('checks appliesTo properties', () => {
        return should(pluginLocal.init({
          passwordPolicies: [
            {
              appliesTo: {
                foo: 'bar'
              }
            }
          ]
        }, pluginContext))
          .be.rejectedWith(assert.AssertionError);
      });

      it('checks appliesTo properties are arrays', () => {
        return should(pluginLocal.init({
          passwordPolicies: [
            {
              appliesTo: {
                users: [],
                profiles: 'this is not valid',
                roles: []
              }
            }
          ]
        }, pluginContext))
          .be.rejectedWith(assert.AssertionError);
      });
    });
  });
});
