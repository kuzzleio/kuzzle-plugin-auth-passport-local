const
  should = require('should'),
  PluginLocal = require('../lib'),
  PluginContext = require('./mock/pluginContext.mock.js');

describe('#search', () => {
  const pluginContext = new PluginContext();
  let
    pluginLocal,
    request;

  beforeEach(async () => {
    pluginLocal = new PluginLocal();
    await pluginLocal.init({}, pluginContext);
    pluginLocal.userRepository = new (require('./mock/getUserRepository.mock')(pluginLocal))();

    request = new pluginContext.constructors.Request({
      body: {
        "query": {
          "bool": {
            "must": [
              {
                "match": {
                  "username":  "foo2"
                }
              }
            ]
          }
        }
      }
    });
  });

  it('should return a search result', async () => {
    const result = await pluginLocal.search(request);

    should(result).eql({ total: 1, hits: [{ username: 'foo2' }] });
  });

  it('should throw an error if the qurey contain forbidden words', () => {
    request = new pluginContext.constructors.Request({
      body: {
        "query": {
          "bool": {
            "must": [
              {
                "match": {
                  "userPassword":  "*****"
                }
              }
            ]
          }
        }
      }
    });
    
    return should(pluginLocal.search(request, 'foo'))
      .be.rejectedWith(pluginContext.context.errors.BadRequestError(
        `Forbidden keyword "userPassword". Search query must only concern the username`));
  });
});
