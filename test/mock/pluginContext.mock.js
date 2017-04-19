let defaultError = function(message) { return {message: message}; };

module.exports = {
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
    ForbiddenError: defaultError
  }
};