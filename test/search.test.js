const should = require('should');
const { BadRequestError, ForbiddenError } = require('kuzzle');

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
      .be.rejectedWith(new ForbiddenError('Forbidden field "algorithm". Only the "username" or "kuid" fields are sortable and only the first is also searchable.'));
  });

  it('should throw an error if the query contains forbidden keyword', () => {
    searchBody.query = {
      multi_match: {
        query: 'sha512', 
        fields: [ 'username', 'algorithm' ] 
      }
    };

    return should(pluginLocal.search(searchBody))
      .be.rejectedWith(new BadRequestError('The "multi_match" keyword is not allowed in this search query for security concerns.'));
  });

  it('should throw an error if the query does not concern username', () => {
    searchBody.query = {
      evil_keyword: {
        query: 'password', 
        fields: [ 'user.*', 'undetectable_wilcard' ] 
      }
    };

    return should(pluginLocal.search(searchBody))
      .be.rejectedWith(new BadRequestError('Only the "username" field is searchable, otherwise leave the query empty.'));
  });

  it('should throw an error if the sort contains forbidden fields', () => {
    searchBody.sort = [{ 'passwordHistory.userSalt': 'asc' }];

    return should(pluginLocal.search(searchBody))
      .be.rejectedWith(new ForbiddenError('Forbidden field "passwordHistory.userSalt". Only the "username" or "kuid" fields are sortable and only the first is also searchable.'));
  });

  it('should throw an error if the sort does not concern username or kuid', () => {
    searchBody.sort = [{
      evil_keyword: {
        order : 'asc',
        fields: ['user.*', 'undetectable_wilcard']
      }
    }];

    return should(pluginLocal.search(searchBody))
      .be.rejectedWith(new BadRequestError('Only the "username" or "kuid" fields are sortable.'));
  });

  it('should not detect required fields when they are part of an array values', async () => {
    // In ES multi fields queries, we can use wildcards which are almost undetectable.
    // If username is in an array, it is likely that multiple fields are listed in there...
    searchBody.query = {
      new_unknown_keyword: {
        query: 'password', 
        fields: [ 'username', 'undetectable_wilcard', 'user.*' ] 
      }
    };

    await pluginLocal.search(searchBody)
      .should.be.rejectedWith(new BadRequestError('Only the "username" field is searchable, otherwise leave the query empty.'));
    
    // But we cannot just throw if an array has non compliant values, this should actually work:
    searchBody.query = {
      terms : {
        username: ['username', 'algorithm', 'foo2']
      }
    };

    const result = await pluginLocal.search(searchBody);

    should(result).eql({ total: 1, hits: [{ kuid:'someId', username: 'foo2' }] });

    // Currently, there is just half the solution. A complex query can still slip through the net.
    // Conclusion: Keep up to date forbiddenKeywords to prevent queries on forbiddenFields

    // Complex query example:
    // searchBody.query = {
    //   bool: {
    //     must: {
    //       match: {
    //         username: 'foo2'
    //       }
    //     },
    //     filter: {
    //       new_unknown_keyword: {
    //         query: 'password', 
    //         fields: [ 'user.*', 'undetectable_wilcard' ] 
    //       }
    //     }
    //   }
    // };
  });
});
