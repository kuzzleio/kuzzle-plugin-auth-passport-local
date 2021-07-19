'use strict';

const should = require('should');
const sinon = require('sinon');
const { objectRecursiveMap, extractESMappingFields } = require('../lib/utils');

describe('#utils', () => {

  describe('#objectRecursiveMap', () => {
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

  describe('#extractESMappingFields', () => {
    let mapping;
    let fieldsToIgnore;

    beforeEach( () => {
      mapping = {
        foo: {
          properties: {
            fooA: {
              type: 'boolean'
            },
            fooB: {
              properties: {
                fooBar: {
                  type: 'keyword'
                }
              },
              type: 'nested'
            }
          }
        }
      };
      fieldsToIgnore = ['fooB'];
    });

    it('should extract fields properly even deeply nested', () => {
      const result = extractESMappingFields(mapping);

      should(result).be.deepEqual(['foo', 'foo.fooA', 'foo.fooB', 'foo.fooB.fooBar']);
    });

    it('should ignore requested fields (and their nested fields)', () => {
      const result = extractESMappingFields(mapping, fieldsToIgnore);

      should(result).be.deepEqual(['foo', 'foo.fooA']);
    });
  });
});
