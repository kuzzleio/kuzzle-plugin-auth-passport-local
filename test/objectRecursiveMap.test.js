'use strict';

const should = require('should');
const sinon = require('sinon');
const { objectRecursiveMap } = require('../lib/utils');

describe('#utils/objectRecursiveMap', () => {
  let object;
  let fn;

  beforeEach(() => {
    object = {
      foo: 'foo',
      bar: { a: 'bar.a', b: 'bar.b' },
      c: [{ array: 'c'}, { array: 'c' }]
    };
    fn = sinon.stub().returns({});
  });

  it('should apply a function on each property and return the object', () => {
    const result = objectRecursiveMap(object, fn);

    should(fn).be.called(7);
    should(result).be.deepEqual(object);
  });

  it('should handle new key or value for mapped objects', () => {
    const result = objectRecursiveMap(object, (key) => {
      if (key === 'array') {
        return { key: 'parent'};
      }
      else if (key === 'b') {
        return { key: 'c', value: 'nested' };
      }
      else if (key === 'bar' || key === 'c') {
        return {};
      }
      return { value: 'default' };
    });

    should(result).be.deepEqual({
      foo: 'default',
      bar: { a: 'default', c: 'nested' },
      c: [{ parent: 'c' }, { parent: 'c' }]
    });
  });
});
