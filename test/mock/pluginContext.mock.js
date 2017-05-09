const
  sinon = require('sinon'),
  defaultError = sinon.stub().callsFake(message => ({message})),
  repository = require('./repository.mock');

module.exports = {
  constructors: {
    Repository: repository,
    Request: sinon.stub()
  },
  accessors: {
    storage: {
      bootstrap: sinon.stub().returns(Promise.resolve())
    },
    execute: sinon.stub().returns(Promise.resolve())
  },
  errors: {
    BadRequestError: defaultError,
    ForbiddenError: defaultError
  }
};
