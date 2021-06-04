/*
 * Kuzzle, a backend software, self-hostable and ready to use
 * to power modern apps
 *
 * Copyright 2015-2020 Kuzzle
 * mailto: support AT kuzzle.io
 * website: http://kuzzle.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

/**
 * 
 * @param {any} object Object to test
 * @returns {boolean} true if it's a plain object, false otherwise
 */
function isPlainObject (object) {
  return object !== null && typeof object === 'object' && !Array.isArray(object);
}

/**
 * 
 * @param {Object} object Plain object to map
 * @param {(key: string, value: any, index: number) => {key: string, value: any}} fn Map function returning an object containing what must be updated (key/value)
 * @returns {Object} Mapped object
 */
const objectRecursiveMap = (object, fn) => {
  return Object.fromEntries(
    Object.entries(object).map(
      ([key, value], index) => {
        let { key: newKey = key, value: newValue = value } = fn(key, value, index);

        if (Array.isArray(newValue)) {
          newValue = newValue.map(item => 
            typeof item === 'object' ? objectRecursiveMap(item, fn) : item);
        }
        else if (typeof newValue === 'object' && newValue !== null) {
          newValue = objectRecursiveMap(newValue, fn);
        }

        return [newKey, newValue];
      }
    )
  );
};

/**
 * Extract fields and their nested field from an ES mapping object in a flat array
 * Example: { field : { 1: "nested", 2: "nested" } } => [ 'field', 'field.1', 'field.2' ]
 * 
 * @param {Object} mappings ES mappings
 * @param {Array<string>} fieldsToIgnore Fields (and their nested fields) which must not be considered
 * @returns {Array<string>} 
 */
function extractESMappingFields(mappings, fieldsToIgnore = [], path = '') {
  let fields = [];
  for (const [key, value] of Object.entries(mappings)) {
    if (key === 'properties') {
      fields = fields.concat(extractESMappingFields(value, fieldsToIgnore, path));
    }
    else if (isPlainObject(value) && !fieldsToIgnore.includes(key)) {
      fields.push(path ? `${path}.${key}` : key);
      fields = fields.concat(
        extractESMappingFields(value, fieldsToIgnore, path ? `${path}.${key}` : key));
    }
  }
  return fields;
}

module.exports = { isPlainObject, objectRecursiveMap, extractESMappingFields };