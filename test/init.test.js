const
  should = require('should'),
  PluginLocal = require('../lib');

describe('#init', () => {
  let
    pluginLocal,
    pluginContext = require('./mock/pluginContext.mock.js');

  beforeEach(() => {
    pluginLocal = new PluginLocal();
    pluginLocal.context = pluginContext;
  });

  it('should initialize a \'local\' strategy', () => {
    should(pluginLocal.strategies).not.be.ok();

    pluginLocal.init(null, pluginContext);

    should(pluginLocal.strategies).be.Object().and.match({
      local: {
        config: {
          constructor: () => {},
          strategyOptions: {},
          authenticateOptions: {
            scope: []
          },
          fields: ['login', 'password'],
          verify: 'verify'
        },
        methods: {
          exists: 'exists',
          validate: 'validate',
          create: 'create',
          update: 'update',
          delete: 'delete',
          getInfo: 'getInfo'
        }
      }
    });
  });

  it('should have a getUserRepository method returning an object', function() {
    pluginLocal.init(null, pluginContext);

    should(pluginLocal.getUsersRepository).be.a.Function();
    should(pluginLocal.getUsersRepository()).be.an.Object();
  });
});
