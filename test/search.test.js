const should = require('should');

const PluginLocal = require('../lib');
const PluginContext = require('./mock/pluginContext.mock.js');

describe('#search', () => {
  const pluginContext = new PluginContext();
  let pluginLocal;
  let searchBody;

  beforeEach(async () => {
    pluginLocal = new PluginLocal();
    await pluginLocal.init({}, pluginContext);
    pluginLocal.userRepository = new (require('./mock/getUserRepository.mock')(pluginLocal))();

    searchBody = {
      query: {
        match: {
          username:  'foo2'
        }
      },
      sort: [
        { kuid: 'asc' },
        { username: 'desc' }
      ]
    };
  });

  it('should return a search result', async () => {
    const result = await pluginLocal.search(searchBody);

    should(result).eql({ total: 1, hits: [{ kuid:'someId', username: 'foo2' }] });
  });

  it('should throw an error if the query contains forbidden fields', () => {
    searchBody.query.match = { algorithm: 'sha512' };

    return should(pluginLocal.search(searchBody))
      .be.rejectedWith({
        message: 'Forbidden field "algorithm". Only the "username" or "kuid" fields are sortable and only the first is also searchable.'
      });
  });

  it('should throw an error if the query contains forbidden keyword', () => {
    searchBody.query = {
      multi_match: {
        query: 'sha512',
        fields: [ 'username', 'algorithm' ]
      }
    };

    return should(pluginLocal.search(searchBody))
      .be.rejectedWith({
        message: 'The "multi_match" keyword is not allowed in this search query for security concerns.'
      });
  });

  it('should throw an error if the sort contains forbidden fields', () => {
    searchBody.sort = [{ 'passwordHistory.userSalt': 'asc' }];

    return should(pluginLocal.search(searchBody))
      .be.rejectedWith({
        message: 'Forbidden field "passwordHistory.userSalt". Only the "username" or "kuid" fields are sortable and only the first is also searchable.'
      });
  });

  it('should throw an error if the sort contains forbidden keyword', () => {
    searchBody.sort = {
      _script: {
        script: {
          source: 'doc[userPassword].value * params.factor',
          params: {
            factor: 1.1
          }
        },
        order: 'asc'
      }
    };

    return should(pluginLocal.search(searchBody))
      .be.rejectedWith({
        message: 'The "_script" keyword is not allowed in this search query for security concerns.'
      });
  });

  it('should ignore forbidden fields when being used as a simple value', async () => {
    searchBody.query = {
      terms : {
        username: ['algorithm', 'multi_match']
      }
    };

    const result = await pluginLocal.search(searchBody);

    should(result).eql({ total: 1, hits: [{ kuid:'someId', username: 'foo2' }] });
  });
});
