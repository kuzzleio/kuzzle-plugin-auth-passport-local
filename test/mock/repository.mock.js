module.exports = function () {
  return {
    get: kuid => kuid === 'ghost' ? Promise.resolve(null) : Promise.resolve({
      _id: 'foo',
      userPassword: '7ea233545318d00c0bc668cbcbf5d7f25416ebc8afe89717c07d4ad48badd1a162a8194075385047d8b548b8903ac60a8c131836731e647911a52fc0233a698ba3f79070e627555de3d80bff88dbb6d9ed0a2dcab2d229c2b0622e4f42a93e573aa1346d292bf30f7a0bdc41f46dcfea209b939582dddbe1ccf37ea499937fbb984ce4054a821a5ae4f43a118a8a9989c66df5787a0d96626e7ec5cea51a1998542663ff19fb4f0cd7414e01be0cdbf00bec37acc0657e009668b8ad01c34a46ac4c1f9bc8865bc3944083010623e2ba4da1535e90f25357a236d1e207bce6a3c8b9e9245ff265bd712a830bd6cbde763fcd6d4f5a0833d84098c0445e517020',
      userSalt: 'someSalt',
      kuid
    }),
    search: () => Promise.resolve({total: 1, hits: [{_id: 'foo2', kuid: 'someId'}]}),
    create: () => Promise.resolve({_id: 'foo', kuid: 'someId'}),
    update: () => Promise.resolve({_id: 'foo', kuid: 'someId'}),
    delete: () => Promise.resolve(true)
  };
};