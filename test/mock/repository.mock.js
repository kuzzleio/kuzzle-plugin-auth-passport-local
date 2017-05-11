module.exports = function () {
  return {
    get: kuid => kuid === 'ghost' ? Promise.resolve(null) : Promise.resolve({
      _id: 'foo',
      userPassword: 'dc7fcdf5a547d21d517c14e3a51b8f51e7a6bdba7b1eedcc44605fc0c450b710',
      kuid
    }),
    search: () => Promise.resolve({total: 1, hits: [{_id: 'foo2', kuid: 'someId'}]}),
    create: () => Promise.resolve({_id: 'foo', kuid: 'someId'}),
    update: () => Promise.resolve({_id: 'foo', kuid: 'someId'}),
    delete: () => Promise.resolve(true)
  };
};