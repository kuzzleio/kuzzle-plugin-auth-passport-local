const
  should = require('should'),
  rewire = require('rewire'),
  PluginLocal = rewire('../lib');

describe('#init', function () {
  let
    pluginLocal,
    pluginContext = rewire('./mock/pluginContext.mock.js');

  beforeEach(function () {
    pluginLocal = new PluginLocal();
  });

  it('should return a Promise', function () {
    should(pluginLocal.init(null, pluginContext)).be.a.Promise();
  });

  it('should initialize a \'local\' strategy', function () {
    should(pluginLocal.strategies).not.be.ok();

    pluginLocal.init(null, pluginContext);

    should(pluginLocal.strategies).be.Object().and.match({
      local: {
        config: {
          constructor: function () {},
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
