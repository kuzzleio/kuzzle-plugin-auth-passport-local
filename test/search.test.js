const
  should = require('should'),
  PluginLocal = require('../lib'),
  PluginContext = require('./mock/pluginContext.mock.js');

describe('#search', () => {
  const pluginContext = new PluginContext();
  let pluginLocal;
  let request;
  let body;

  beforeEach(async () => {
    pluginLocal = new PluginLocal();
    await pluginLocal.init({}, pluginContext);
    pluginLocal.userRepository = new (require('./mock/getUserRepository.mock')(pluginLocal))();

    body = {
      query: {
        bool: {
          must: [
            {
              match: {
                username:  'foo2'
              }
            }
          ]
        }
      }
    };

    request = new pluginContext.constructors.Request({body});

    // TODO update kuzzle-common-objects
    // eslint-disable-next-line no-unused-vars
    request.getBodyObject = (query) => body;
  });

  it('should return a search result', async () => {
    const result = await pluginLocal.search(request);

    should(result).eql({ total: 1, hits: [{ kuid:'foo', username: 'foo2' }] });
  });

  it('should throw an error if the qurey contain forbidden words', () => {
    request = new pluginContext.constructors.Request({
      body: {
        query: {
          bool: {
            must: [
              {
                match: {
                  userPassword:  '*****'
                }
              }
            ]
          }
        }
      }
    });

    return should(pluginLocal.search(request, 'foo'))
      .be.rejectedWith(new pluginContext.context.errors.BadRequestError(
        `Forbidden keyword "userPassword". Search query must only concern the username`));
  });
});
