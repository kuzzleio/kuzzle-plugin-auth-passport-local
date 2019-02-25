const
  sinon = require('sinon'),
  defaultError = sinon.stub().callsFake(message => ({message})),
  repository = require('./repository.mock');

module.exports = function () {
  return {
    constructors: {
      Repository: repository,
      Request: sinon.stub()
    },
    config: {
      version: '1.4.0'
    },
    accessors: {
      storage: {
        bootstrap: sinon.stub().returns(Promise.resolve())
      },
      execute: sinon.stub().returns(Promise.resolve())
    },
    errors: {
      BadRequestError: defaultError,
      ForbiddenError: defaultError,
      PluginImplementationError: defaultError,
      PreconditionError: defaultError
    }
  };
};
