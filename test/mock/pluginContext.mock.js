const
  sinon = require('sinon'),
  defaultError = sinon.stub().callsFake(message => {return {message}});

module.exports = {
  constructors: {
    Repository: sinon.stub(),
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
