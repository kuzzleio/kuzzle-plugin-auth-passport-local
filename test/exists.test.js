const
  should = require('should'),
  rewire = require('rewire'),
  PluginLocal = rewire('../lib');

describe('#exists', function () {
  let
    pluginLocal,
    pluginContext = rewire('./mock/pluginContext.mock.js'),
    repository = rewire('./mock/repository.mock.js');

  beforeEach(function () {
    pluginLocal = new PluginLocal();
    pluginLocal.getUsersRepository = repository;

    pluginLocal.init(null, pluginContext);
  });

  it('should return true if the user already exists', function() {
    pluginLocal.exists(null, 'foo')
      .then(result => {
        should(result).be.True();
      });
  });

  it('should return false if the user doesn\'t exists', function() {
    pluginLocal.getUsersRepository = () => {
      return {
        search: () => Promise.resolve({total: 0, hits: []})
      };
    };

    pluginLocal.exists(null, 'foo')
      .then(result => {
        should(result).be.False();
      });
  });
});
