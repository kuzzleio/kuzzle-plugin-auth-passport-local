const
  should = require('should'),
  rewire = require('rewire'),
  PluginLocal = rewire('../lib');

describe('#validate', function () {
  let
    pluginLocal,
    pluginContext = rewire('./mock/pluginContext.mock.js'),
    repository = rewire('./mock/repository.mock.js');

  beforeEach(function () {
    pluginLocal = new PluginLocal();
    pluginLocal.getUsersRepository = repository;

    pluginLocal.init(null, pluginContext);
  });

  it('should throw an error if the credentials are not well-formed', function(done) {
    pluginLocal.validate(null, {}, 'foo')
      .then(() => {
        done(new Error('Should not have succeeded'));
      })
      .catch(error => {
        should(error.message).match('Username is a mandatory field for authentication strategy "local".');
        done();
      });
  });

  it('should throw an error if the userId is provided in the credentials', function(done) {
    pluginLocal.validate(null, {userId: 'foo', username: 'bar'}, 'foo')
      .then(() => {
        done(new Error('Should not have succeeded'));
      })
      .catch(error => {
        should(error.message).be.eql('userId cannot be specified in credentials.');
        done();
      });
  });

  it('should return true if the provided username equals the userId', function() {
    pluginLocal.validate(null, {username:'foo', password:'bar'}, 'foo')
      .then(result => {
        should(result).be.True();
      });
  });

  it('should return true if no user was found for the given userId', function() {
    pluginLocal.validate(null, {username:'ghost', password:'bar'}, 'foo')
      .then(result => {
        should(result).be.True();
      });
  });

  it('should throw an error if the provided username differs from the userId', function(done) {
    let unmatchingUsername = 'bar';

    pluginLocal.validate(null, {username: unmatchingUsername, password: 'bar'}, 'foo')
      .then(() => {
        done(new Error('Should not have succeeded'));
      })
      .catch(error => {
        should(error.message).be.eql(`Login "${unmatchingUsername}" is already used.`);
        done();
      });
  });
});
