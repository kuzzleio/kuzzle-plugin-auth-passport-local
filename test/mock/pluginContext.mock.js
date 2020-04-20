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
          }),
          mGetProfiles: sinon.stub().callsFake(async profileIds => profileIds.map(profileId => ({
            _id: profileId,
            policies: [
              {roleId: `role for ${profileId}`}
            ]
          })))
        }
      },
      storage: {
        bootstrap: sinon.stub().resolves()
      },
      execute: sinon.stub().resolves({result: true})
    },
    config: {
      version: '1.4.0'
    },
    constructors: {
      Repository: function () {
        this.create = sinon.stub().resolves();
        this.get = sinon.stub().resolves();
      },
      Request
    },
    errors
  };
};
