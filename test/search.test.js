const
  should = require('should'),
  PluginLocal = require('../lib'),
  PluginContext = require('./mock/pluginContext.mock.js');

describe('#search', () => {
  const pluginContext = new PluginContext();
  let pluginLocal;
  let query;

  beforeEach(async () => {
    pluginLocal = new PluginLocal();
    await pluginLocal.init({}, pluginContext);
    pluginLocal.userRepository = new (require('./mock/getUserRepository.mock')(pluginLocal))();
    global.kuzzle = { config: { limits: { documentsFetchCount: 10000 } } };

    query = {
      bool: {
        must: [
          {
            match: {
              username:  'foo2'
            }
          }
        ]
      }
    };
  });

  it('should return a search result', async () => {
    const result = await pluginLocal.search(query);

    should(result).eql({ total: 1, hits: [{ kuid:'someId', username: 'foo2' }] });
  });

  it('should throw an error if the query contain forbidden words', () => {
    query.bool.must[0].match = { algorithm: 'sha512' };

    return should(pluginLocal.search(query))
      .be.rejectedWith(new pluginLocal.context.errors.BadRequestError(
        `Forbidden keyword "algorithm". Search query must only concern username property`));
  });
});
