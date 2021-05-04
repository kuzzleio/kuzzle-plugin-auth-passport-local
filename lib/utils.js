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
 * Throws if the given object has any forbidden key even deeply nested.
 * 
 * @param {object} object
 * @param {Array<string>} forbiddenKeys
 * @param {(key: string) => Error} errorToThrow
 */
function verifyKeys(object, forbiddenKeys, errorToThrow) {
  if ( ! forbiddenKeys.length ) {
    return;
  }
  for (const [key, value] in object) {
    if ( forbiddenKeys.find(forbiddenKey => forbiddenKey === key) ) {
      throw errorToThrow(key);
    }
    if (typeof value === 'object') {
      verifyKeys(value, forbiddenKeys);
    }
  }
}

module.exports = verifyKeys