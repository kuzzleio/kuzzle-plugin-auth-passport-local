const
  should = require('should'),
  rewire = require('rewire'),
  PluginLocal = rewire('../lib');

describe('#verify', function () {
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

  it('should return the username if the credentials are valid', function() {
    pluginLocal.verify(null, 'foo', 'bar')
      .then(result => {
        should(result === 'foo').be.True();
      });
  });

  it('should throw an error if no user was found for the given username', function(done) {
    pluginLocal.verify(null, 'ghost', 'bar')
      .then(() => {
        done(new Error('Should not have succeeded'));
      })
      .catch(error => {
        should(error.message).be.eql('Login failed');
        done();
      });
  });

  it('should throw an error if the credentials are invalid', function(done) {
    pluginLocal.verify(null, 'foo', 'rab')
      .then(() => {
        done(new Error('Should not have succeeded'));
      })
      .catch(error => {
        should(error.message).be.eql('Login failed');
        done();
      });
  });
});
