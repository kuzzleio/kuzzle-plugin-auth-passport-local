const sinon = require('sinon');
const {
  KuzzleRequest,
  BadRequestError,
  PreconditionError,
  ForbiddenError,
  NotFoundError,
  UnauthorizedError,
} = require('kuzzle');

const manifest = require('../../manifest.json');

const errors = {
  BadRequestError,
  PreconditionError,
  ForbiddenError,
  NotFoundError,
  UnauthorizedError,
};

const getError = id => {
  const info = manifest.errors[id];
  const error = new errors[info.class](
    info.message,
    `plugin.${manifest.name}.${id}`,
    0x004000000 + info.code
  );
  return error;
};


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
      Request: KuzzleRequest
    },
    errors,
    errorsManager: {
      get: getError,
      throw: id => { throw getError(id); }
    }
  };
};
