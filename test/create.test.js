const
  should = require('should'),
  rewire = require('rewire'),
  PluginLocal = rewire('../lib');

describe('#create', function () {
  let
    pluginLocal,
    pluginContext = rewire('./mock/pluginContext.mock.js'),
    repository = rewire('./mock/repository.mock.js');

  beforeEach(function () {
    pluginLocal = new PluginLocal();
    pluginLocal.getUsersRepository = repository;
    pluginLocal.passwordManager = require('./mock/passwordManager.mock');

    pluginLocal.init(null, pluginContext);
  });

  it('should return a user object if the user doesn\'t exists', function() {
    pluginLocal.getUsersRepository = () => {
      return {
        search: () => Promise.resolve({total: 0, hits: []}),
        create: () => Promise.resolve({_id: 'foo'})
      };
    };

    pluginLocal.create(null, {username: 'foo', password: 'bar'}, 'foo')
      .then(result => {
        should(result).match({username: 'foo'});
      });
  });

  it('should throw an error if the user already exists', function(done) {
    pluginLocal.create(null, {username: 'foo', password: 'bar'}, 'foo')
      .then(() => {
        done(new Error('Should not have succeeded'));
      })
      .catch(error => {
        should(error.message).be.eql('A strategy already exists for this user.');
        done();
      });
  });
});
