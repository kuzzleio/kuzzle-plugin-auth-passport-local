const
  sinon = require('sinon'),
  { Request, errors } = require('kuzzle-common-objects');

module.exports = function PluginContext() {
  return {
    accessors: {
      sdk: {
        security: {
          getUser: sinon.stub().callsFake(async kuid => {
            return {
              _id: kuid,
              content: {
                profileIds: ['profile1', 'profile2']
              }
            };
          })
        }
      },
      storage: {
        bootstrap: sinon.stub().returns(Promise.resolve())
      },
      execute: sinon.stub().returns(Promise.resolve())
    },
    config: {
      version: '1.4.0'
    },
    constructors: {
      Repository: function () {
        this.create = sinon.stub().resolves();
      },
      Request
    },
    errors
  };
};
