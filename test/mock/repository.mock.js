module.exports = function () {
  return {
    get: userId => userId === 'ghost' ? Promise.resolve(null) : Promise.resolve({userId: userId, userPassword: 'dc7fcdf5a547d21d517c14e3a51b8f51e7a6bdba7b1eedcc44605fc0c450b710'}),
    search: () => Promise.resolve({total: 1, hits: [{_id: 'foo2'}]}),
    create: () => Promise.resolve({_id: 'foo'}),
    update: () => Promise.resolve({_id: 'foo'}),
    delete: () => Promise.resolve(true)
  };
};