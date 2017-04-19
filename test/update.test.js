const
  should = require('should'),
  rewire = require('rewire'),
  PluginLocal = rewire('../lib');

describe('#update', function () {
  let
    pluginLocal,
    pluginContext = rewire('./mock/pluginContext.mock.js'),
    repository = rewire('./mock/repository.mock.js');

  beforeEach(function () {
    pluginLocal = new PluginLocal();
    pluginLocal.getUsersRepository = repository;

    let defaultError = function(message) { return {message: message}; };

    pluginContext = {
      constructors: {
        Repository: function() {}
      },
      accessors: {
        storage: {
          bootstrap: () => new Promise(() => {})
        }
      },
      errors: {
        BadRequestError: defaultError,
        ForbiddenError:defaultError
      }
    };

    pluginLocal.init(null, pluginContext);
  });

  it('should throw an error if the user doesn\'t exists', function(done) {
    pluginLocal.getUsersRepository = () => {
      return {
        search: () => Promise.resolve({total: 0, hits: []})
      };
    };

    pluginLocal.update(null, {username: 'foo', password: 'bar'}, 'foo')
      .then(() => {
        done(new Error('Should not have succeeded'));
      })
      .catch(error => {
        should(error.message).be.eql('A strategy does not exist for this user.');
        done();
      });
  });

  it('it should update the user and its username if the credentials are valid', function() {
    pluginLocal.update(null, {username: 'foo', password: 'bar'}, 'foo')
      .then(result => {
        should(result).match({username: 'foo'});
      });
  });

  it('it should update the user if the credentials are valid', function() {
    pluginLocal.getUsersRepository = () => {
      return {
        get: userId => Promise.resolve({userId: userId}),
        search: () => Promise.resolve({total: 1, hits: [{_id: 'foo'}]}),
        update: () => Promise.resolve({_id: 'foo'})
      };
    };

    pluginLocal.update(null, {username: 'foo', password: 'bar'}, 'foo')
      .then(result => {
        should(result).match({_id: 'foo'});
      });
  });
});
