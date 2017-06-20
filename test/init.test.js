const
  should = require('should'),
  PluginLocal = require('../lib');

describe('#init', () => {
  const pluginContext = require('./mock/pluginContext.mock.js');
  let pluginLocal;

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

  it('should have a getUserRepository method returning an object', function() {
    pluginLocal.init(null, pluginContext);

    should(pluginLocal.getUsersRepository).be.a.Function();
    should(pluginLocal.getUsersRepository()).be.an.Object();
  });
});
