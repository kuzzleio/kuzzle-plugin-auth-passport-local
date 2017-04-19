const
  should = require('should'),
  rewire = require('rewire'),
  PluginLocal = rewire('../lib');

describe('#delete', function () {
  let
    pluginLocal,
    pluginContext = rewire('./mock/pluginContext.mock.js'),
    repository = rewire('./mock/repository.mock.js');

  beforeEach(function () {
    pluginLocal = new PluginLocal();
    pluginLocal.getUsersRepository = repository;

    pluginLocal.init(null, pluginContext);
  });

  it('should return true if the user exists', function() {
    pluginLocal.delete(null, 'foo')
      .then(result => {
        should(result).be.True();
      });
  });

  it('should throw an error if the user doesn\'t exists', function(done) {
    pluginLocal.getUsersRepository = () => {
      return {
        search: () => Promise.resolve({total: 0, hits: []})
      };
    };

    pluginLocal.delete(null, 'ghost')
      .then(() => {
        done(new Error('Should not have succeeded'));
      })
      .catch(error => {
        should(error.message).be.eql('A strategy does not exist for this user.');
        done();
      });
  });
});
